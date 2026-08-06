//! D-02T8 timestamped rotation for monotonic pending-context mappings.
//!
//! A fresh pending namespace writes three physical rows: pending to checkpoint,
//! pending to proc UUID, and proc UUID to pending. Old namespaces are preserved;
//! this module deliberately exposes no DELETE. The monotonic counter allocation
//! remains a separate LWT concern for a later slice.
//!
//! The executable adapter is intentionally private:
//!
//! ```compile_fail
//! use psy_node_scylla::rollback::PendingContextAdapter;
//! ```

use std::{error::Error, fmt};

use psy_node_core::store::typed::{
    CheckpointId, MutationOperation, MutationValue, ProcCheckpointUniqueId,
    TypedTableKey, UniquePendingId,
};
use scylla::{
    client::session::Session,
    statement::{prepared::PreparedStatement, Consistency},
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::utils::u64_to_i64_exact;

use super::{
    physical_descriptor, CqlKeyspaceName, PrototypeBindValue,
    ScyllaPhysicalTableId, SealedTimestampedPut,
    SealedTimestampedPutBatch, TimestampedWriteKind,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PendingContextTransitionKind {
    AuthorityRotation = 1,
    RollbackRotation = 2,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingContext {
    pending: UniquePendingId,
    proc_id: ProcCheckpointUniqueId,
}

impl PendingContext {
    pub fn try_new(
        pending: UniquePendingId,
        proc_id: ProcCheckpointUniqueId,
    ) -> Result<Self, PendingContextPlanError> {
        let pending_is_zero = pending.get() == 0;
        let proc_is_zero = proc_id.as_u128() == 0;
        if pending_is_zero != proc_is_zero {
            return Err(PendingContextPlanError::InconsistentZeroContext);
        }
        Ok(Self { pending, proc_id })
    }

    pub const fn pending(self) -> UniquePendingId {
        self.pending
    }

    pub const fn proc_id(self) -> ProcCheckpointUniqueId {
        self.proc_id
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PendingContextQueryKind {
    PendingToCheckpointPut = 1,
    PendingToProcPut = 2,
    ProcToPendingPut = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingContextQuery {
    kind: PendingContextQueryKind,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl PendingContextQuery {
    pub const fn kind(&self) -> PendingContextQueryKind {
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
pub struct PendingContextQueries {
    pending_to_checkpoint_put: PendingContextQuery,
    pending_to_proc_put: PendingContextQuery,
    proc_to_pending_put: PendingContextQuery,
}

impl PendingContextQueries {
    pub fn new(keyspace: &CqlKeyspaceName) -> Self {
        let pending_to_checkpoint = physical_descriptor(
            ScyllaPhysicalTableId::PendingIdToCheckpointId,
        )
        .physical_name;
        let pending_to_proc = physical_descriptor(
            ScyllaPhysicalTableId::PendingIdToPendingProcIdU64ToU128,
        )
        .physical_name;
        let proc_to_pending = physical_descriptor(
            ScyllaPhysicalTableId::PendingIdToPendingProcIdU128ToU64,
        )
        .physical_name;
        Self {
            pending_to_checkpoint_put: PendingContextQuery {
                kind: PendingContextQueryKind::PendingToCheckpointPut,
                cql: format!(
                    "INSERT INTO {}.{pending_to_checkpoint} (obj_id, value) VALUES (?, ?) USING TIMESTAMP ?",
                    keyspace.as_str()
                ),
                bind_shape: &[
                    "pending_id:BIGINT",
                    "checkpoint_id:BIGINT",
                    "write_timestamp_us:BIGINT",
                ],
            },
            pending_to_proc_put: PendingContextQuery {
                kind: PendingContextQueryKind::PendingToProcPut,
                cql: format!(
                    "INSERT INTO {}.{pending_to_proc} (obj_id, value) VALUES (?, ?) USING TIMESTAMP ?",
                    keyspace.as_str()
                ),
                bind_shape: &[
                    "pending_id:BIGINT",
                    "proc_id:UUID",
                    "write_timestamp_us:BIGINT",
                ],
            },
            proc_to_pending_put: PendingContextQuery {
                kind: PendingContextQueryKind::ProcToPendingPut,
                cql: format!(
                    "INSERT INTO {}.{proc_to_pending} (obj_id, value) VALUES (?, ?) USING TIMESTAMP ?",
                    keyspace.as_str()
                ),
                bind_shape: &[
                    "proc_id:UUID",
                    "pending_id:BIGINT",
                    "write_timestamp_us:BIGINT",
                ],
            },
        }
    }

    pub const fn pending_to_checkpoint_put(&self) -> &PendingContextQuery {
        &self.pending_to_checkpoint_put
    }

    pub const fn pending_to_proc_put(&self) -> &PendingContextQuery {
        &self.pending_to_proc_put
    }

    pub const fn proc_to_pending_put(&self) -> &PendingContextQuery {
        &self.proc_to_pending_put
    }

    pub fn render_golden(&self) -> String {
        let mut output = String::new();
        for query in [
            self.pending_to_checkpoint_put(),
            self.pending_to_proc_put(),
            self.proc_to_pending_put(),
        ] {
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
pub struct PendingContextPlanDigest([u8; 32]);

impl PendingContextPlanDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingToCheckpointBinding {
    pending: UniquePendingId,
    checkpoint: CheckpointId,
    write_timestamp_us: i64,
}

impl PendingToCheckpointBinding {
    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::BigInt(u64_to_i64_exact(self.pending.get())),
            PrototypeBindValue::BigInt(u64_to_i64_exact(self.checkpoint.get())),
            PrototypeBindValue::BigInt(self.write_timestamp_us),
        ]
    }

    fn driver_values(&self) -> (i64, i64, i64) {
        (
            u64_to_i64_exact(self.pending.get()),
            u64_to_i64_exact(self.checkpoint.get()),
            self.write_timestamp_us,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingToProcBinding {
    pending: UniquePendingId,
    proc_id: ProcCheckpointUniqueId,
    write_timestamp_us: i64,
}

impl PendingToProcBinding {
    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::BigInt(u64_to_i64_exact(self.pending.get())),
            PrototypeBindValue::Uuid(*self.proc_id.as_bytes()),
            PrototypeBindValue::BigInt(self.write_timestamp_us),
        ]
    }

    fn driver_values(&self) -> (i64, Uuid, i64) {
        (
            u64_to_i64_exact(self.pending.get()),
            Uuid::from_u128(self.proc_id.as_u128()),
            self.write_timestamp_us,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcToPendingBinding {
    proc_id: ProcCheckpointUniqueId,
    pending: UniquePendingId,
    write_timestamp_us: i64,
}

impl ProcToPendingBinding {
    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::Uuid(*self.proc_id.as_bytes()),
            PrototypeBindValue::BigInt(u64_to_i64_exact(self.pending.get())),
            PrototypeBindValue::BigInt(self.write_timestamp_us),
        ]
    }

    fn driver_values(&self) -> (Uuid, i64, i64) {
        (
            Uuid::from_u128(self.proc_id.as_u128()),
            u64_to_i64_exact(self.pending.get()),
            self.write_timestamp_us,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingContextMappingPlan {
    kind: PendingContextTransitionKind,
    previous: PendingContext,
    candidate: PendingContext,
    checkpoint: CheckpointId,
    pending_to_checkpoint: PendingToCheckpointBinding,
    pending_to_proc: PendingToProcBinding,
    proc_to_pending: ProcToPendingBinding,
    digest: PendingContextPlanDigest,
}

impl PendingContextMappingPlan {
    pub fn try_for_commit(
        mapping: &SealedTimestampedPut,
        pair: &SealedTimestampedPutBatch,
        previous: PendingContext,
        checkpoint: CheckpointId,
    ) -> Result<Self, PendingContextPlanError> {
        Self::try_build(
            mapping,
            pair,
            previous,
            checkpoint,
            PendingContextTransitionKind::AuthorityRotation,
        )
    }

    pub fn try_for_rollback(
        mapping: &SealedTimestampedPut,
        pair: &SealedTimestampedPutBatch,
        previous: PendingContext,
        target: CheckpointId,
    ) -> Result<Self, PendingContextPlanError> {
        Self::try_build(
            mapping,
            pair,
            previous,
            target,
            PendingContextTransitionKind::RollbackRotation,
        )
    }

    fn try_build(
        mapping: &SealedTimestampedPut,
        pair: &SealedTimestampedPutBatch,
        previous: PendingContext,
        checkpoint: CheckpointId,
        kind: PendingContextTransitionKind,
    ) -> Result<Self, PendingContextPlanError> {
        let expected_write_kind = match kind {
            PendingContextTransitionKind::AuthorityRotation => {
                TimestampedWriteKind::AuthorityCommit
            }
            PendingContextTransitionKind::RollbackRotation => {
                TimestampedWriteKind::NewBranchAfterFence
            }
        };
        require_write_kind(mapping.write_kind(), expected_write_kind)?;
        require_physical(
            mapping.resolved().mutation().physical_table(),
            ScyllaPhysicalTableId::PendingIdToCheckpointId,
        )?;
        let mapping_pending = match mapping.resolved().mutation().key() {
            TypedTableKey::PendingToCheckpoint(pending) => *pending,
            _ => return Err(PendingContextPlanError::WrongTypedKey),
        };
        let mapping_checkpoint = cql_u64(mapping)?;
        if mapping_checkpoint != checkpoint.get() {
            return Err(PendingContextPlanError::CheckpointMismatch {
                expected: checkpoint.get(),
                actual: mapping_checkpoint,
            });
        }

        if pair.members().len() != 2 {
            return Err(PendingContextPlanError::ExpectedPair {
                actual: pair.members().len(),
            });
        }
        let forward = &pair.members()[0];
        let reverse = &pair.members()[1];
        require_write_kind(forward.write_kind(), expected_write_kind)?;
        require_write_kind(reverse.write_kind(), expected_write_kind)?;
        require_physical(
            forward.resolved().mutation().physical_table(),
            ScyllaPhysicalTableId::PendingIdToPendingProcIdU64ToU128,
        )?;
        require_physical(
            reverse.resolved().mutation().physical_table(),
            ScyllaPhysicalTableId::PendingIdToPendingProcIdU128ToU64,
        )?;
        let forward_pending = match forward.resolved().mutation().key() {
            TypedTableKey::PendingToProc(pending) => *pending,
            _ => return Err(PendingContextPlanError::WrongTypedKey),
        };
        let forward_proc = ProcCheckpointUniqueId::from_u128(cql_u128(forward)?);
        let reverse_proc = match reverse.resolved().mutation().key() {
            TypedTableKey::ProcToPending(proc_id) => *proc_id,
            _ => return Err(PendingContextPlanError::WrongTypedKey),
        };
        let reverse_pending = cql_u64(reverse)?;
        if mapping_pending != forward_pending
            || mapping_pending.get() != reverse_pending
            || forward_proc != reverse_proc
        {
            return Err(PendingContextPlanError::InconsistentMappingDirections);
        }

        let expected_pending_raw = previous
            .pending()
            .get()
            .checked_add(1)
            .ok_or(PendingContextPlanError::PendingOverflow)?;
        let expected_pending = UniquePendingId::try_new(expected_pending_raw)
            .map_err(|_| PendingContextPlanError::PendingOverflow)?;
        if mapping_pending != expected_pending {
            return Err(PendingContextPlanError::PendingNotNext {
                previous: previous.pending().get(),
                candidate: mapping_pending.get(),
            });
        }
        if forward_proc.as_u128() == 0 {
            return Err(PendingContextPlanError::ZeroCandidateProcId);
        }
        if forward_proc == previous.proc_id() {
            return Err(PendingContextPlanError::ProcIdNotRotated);
        }
        if mapping.timestamp() != forward.timestamp()
            || mapping.timestamp() != reverse.timestamp()
        {
            return Err(PendingContextPlanError::MixedWriteTimestamps);
        }

        let candidate = PendingContext::try_new(mapping_pending, forward_proc)?;
        let timestamp = mapping.timestamp().as_i64();
        let pending_to_checkpoint = PendingToCheckpointBinding {
            pending: candidate.pending(),
            checkpoint,
            write_timestamp_us: timestamp,
        };
        let pending_to_proc = PendingToProcBinding {
            pending: candidate.pending(),
            proc_id: candidate.proc_id(),
            write_timestamp_us: timestamp,
        };
        let proc_to_pending = ProcToPendingBinding {
            proc_id: candidate.proc_id(),
            pending: candidate.pending(),
            write_timestamp_us: timestamp,
        };
        let digest = plan_digest(
            kind,
            previous,
            candidate,
            checkpoint,
            mapping.canonical_bytes(),
            pair,
        );
        Ok(Self {
            kind,
            previous,
            candidate,
            checkpoint,
            pending_to_checkpoint,
            pending_to_proc,
            proc_to_pending,
            digest,
        })
    }

    pub const fn kind(&self) -> PendingContextTransitionKind {
        self.kind
    }

    pub const fn previous(&self) -> PendingContext {
        self.previous
    }

    pub const fn candidate(&self) -> PendingContext {
        self.candidate
    }

    pub const fn checkpoint(&self) -> CheckpointId {
        self.checkpoint
    }

    pub const fn pending_to_checkpoint(&self) -> &PendingToCheckpointBinding {
        &self.pending_to_checkpoint
    }

    pub const fn pending_to_proc(&self) -> &PendingToProcBinding {
        &self.pending_to_proc
    }

    pub const fn proc_to_pending(&self) -> &ProcToPendingBinding {
        &self.proc_to_pending
    }

    pub const fn digest(&self) -> PendingContextPlanDigest {
        self.digest
    }
}

fn cql_u64(sealed: &SealedTimestampedPut) -> Result<u64, PendingContextPlanError> {
    match sealed.resolved().mutation().operation() {
        MutationOperation::Put(MutationValue::CqlU64(value)) => Ok(*value),
        _ => Err(PendingContextPlanError::ExpectedCqlU64),
    }
}

fn cql_u128(
    sealed: &SealedTimestampedPut,
) -> Result<u128, PendingContextPlanError> {
    match sealed.resolved().mutation().operation() {
        MutationOperation::Put(MutationValue::CqlU128(value)) => Ok(*value),
        _ => Err(PendingContextPlanError::ExpectedCqlU128),
    }
}

fn require_physical(
    actual: ScyllaPhysicalTableId,
    expected: ScyllaPhysicalTableId,
) -> Result<(), PendingContextPlanError> {
    if actual == expected {
        Ok(())
    } else {
        Err(PendingContextPlanError::WrongPhysicalTable { expected, actual })
    }
}

fn require_write_kind(
    actual: TimestampedWriteKind,
    expected: TimestampedWriteKind,
) -> Result<(), PendingContextPlanError> {
    if actual == expected {
        Ok(())
    } else {
        Err(PendingContextPlanError::WrongWriteKind { expected, actual })
    }
}

fn plan_digest(
    kind: PendingContextTransitionKind,
    previous: PendingContext,
    candidate: PendingContext,
    checkpoint: CheckpointId,
    mapping: &[u8],
    pair: &SealedTimestampedPutBatch,
) -> PendingContextPlanDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"psy/pending-context-rotation/v1");
    hasher.update([kind as u8]);
    hasher.update(previous.pending().get().to_be_bytes());
    hasher.update(previous.proc_id().as_bytes());
    hasher.update(candidate.pending().get().to_be_bytes());
    hasher.update(candidate.proc_id().as_bytes());
    hasher.update(checkpoint.get().to_be_bytes());
    hasher.update((mapping.len() as u32).to_be_bytes());
    hasher.update(mapping);
    hasher.update(pair.intent_digest().as_bytes());
    PendingContextPlanDigest(hasher.finalize().into())
}

struct PreparedPendingContext {
    pending_to_checkpoint_put: PreparedStatement,
    pending_to_proc_put: PreparedStatement,
    proc_to_pending_put: PreparedStatement,
}

#[allow(dead_code)]
pub(crate) struct PendingContextAdapter {
    queries: PendingContextQueries,
    prepared: PreparedPendingContext,
}

#[allow(dead_code)]
impl PendingContextAdapter {
    pub(crate) async fn prepare_with_consistency(
        session: &Session,
        keyspace: CqlKeyspaceName,
        consistency: Consistency,
    ) -> anyhow::Result<Self> {
        let queries = PendingContextQueries::new(&keyspace);
        let prepared = PreparedPendingContext {
            pending_to_checkpoint_put: prepare(
                session,
                queries.pending_to_checkpoint_put().cql(),
                consistency,
            )
            .await?,
            pending_to_proc_put: prepare(
                session,
                queries.pending_to_proc_put().cql(),
                consistency,
            )
            .await?,
            proc_to_pending_put: prepare(
                session,
                queries.proc_to_pending_put().cql(),
                consistency,
            )
            .await?,
        };
        Ok(Self { queries, prepared })
    }

    pub(crate) const fn queries(&self) -> &PendingContextQueries {
        &self.queries
    }

    /// Writes the forward direction first because current-context readers use
    /// it. D-04 must persist the plan before counter allocation and recover any
    /// remaining steps before publishing the context as active.
    pub(crate) async fn apply(
        &self,
        session: &Session,
        plan: &PendingContextMappingPlan,
    ) -> anyhow::Result<()> {
        session
            .execute_unpaged(
                &self.prepared.pending_to_proc_put,
                plan.pending_to_proc.driver_values(),
            )
            .await?;
        session
            .execute_unpaged(
                &self.prepared.proc_to_pending_put,
                plan.proc_to_pending.driver_values(),
            )
            .await?;
        session
            .execute_unpaged(
                &self.prepared.pending_to_checkpoint_put,
                plan.pending_to_checkpoint.driver_values(),
            )
            .await?;
        Ok(())
    }
}

async fn prepare(
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
pub enum PendingContextPlanError {
    InconsistentZeroContext,
    WrongPhysicalTable {
        expected: ScyllaPhysicalTableId,
        actual: ScyllaPhysicalTableId,
    },
    WrongTypedKey,
    ExpectedCqlU64,
    ExpectedCqlU128,
    WrongWriteKind {
        expected: TimestampedWriteKind,
        actual: TimestampedWriteKind,
    },
    ExpectedPair { actual: usize },
    CheckpointMismatch { expected: u64, actual: u64 },
    InconsistentMappingDirections,
    PendingOverflow,
    PendingNotNext { previous: u64, candidate: u64 },
    ZeroCandidateProcId,
    ProcIdNotRotated,
    MixedWriteTimestamps,
}

impl fmt::Display for PendingContextPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pending context plan rejected: {self:?}")
    }
}

impl Error for PendingContextPlanError {}
