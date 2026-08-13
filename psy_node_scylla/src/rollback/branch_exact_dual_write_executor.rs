//! Explicit-timestamp legacy/target executor for one durable h22 intent.
//!
//! The adapter is deliberately isolated from production setup.  It accepts
//! only an h20 ready token plus h22b `WritePrepared`, preflights every row,
//! writes all six/eight physical mutations with one sealed timestamp, and
//! constructs verification evidence only from exact value + `writetime`
//! readback.

#![allow(dead_code)]

use std::{cmp::Ordering, error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    authority_commit::AuthorityTimestampKey,
    branch_exact_dual_write::{
        BranchExactDualWriteIntent, BranchExactDualWriteIntentDigest,
        BranchExactDualWriteMutationKind,
        SealedBranchExactDualWrite,
    },
    branch_exact_schema::AuthorityScope,
    timestamp::CommitWriteTimestampUs,
};
use sha2::{Digest, Sha256};
use scylla::{
    client::session::Session,
    statement::{prepared::PreparedStatement, Consistency},
};
use uuid::Uuid;

use super::{
    BranchExactQueries, BranchExactQueryId, BranchExactSchemaReady,
    BranchExactSchemaReadyDigest, BranchExactWriterLifecycleError,
    BranchExactWriterState, BranchExactWriterWriteOutcome,
    CqlKeyspaceName, ScyllaAuthorityTimestampStore,
    ScyllaBranchExactWriterLifecycleStore, SealedBranchExactWriterCas,
    StoredBranchExactWriterLifecycle,
};

const LEGACY_REWARD_PROOF_OBJ_ID: i64 = 2;
const OBSERVATION_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-write-observation/v1";
const ROW_OBSERVATION_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-write-row-observation/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum BranchExactDualWriteQueryId {
    LegacyCheckpointToPendingPut = 1,
    LegacyCheckpointToPendingRead = 2,
    LegacyPendingToCheckpointPut = 3,
    LegacyPendingToCheckpointRead = 4,
    LegacyPendingToProcPut = 5,
    LegacyPendingToProcRead = 6,
    LegacyProcToPendingPut = 7,
    LegacyProcToPendingRead = 8,
    LegacyPendingRewardProofPut = 9,
    LegacyPendingRewardProofRead = 10,
    TargetBranchToPendingPut = 11,
    TargetBranchToPendingRead = 12,
    TargetPendingToBranchPut = 13,
    TargetPendingToBranchRead = 14,
    TargetPendingRewardProofPut = 15,
    TargetPendingRewardProofRead = 16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactDualWriteQuery {
    id: BranchExactDualWriteQueryId,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl BranchExactDualWriteQuery {
    pub const fn id(&self) -> BranchExactDualWriteQueryId {
        self.id
    }

    pub fn cql(&self) -> &str {
        &self.cql
    }

    pub const fn bind_shape(&self) -> &'static [&'static str] {
        self.bind_shape
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactDualWriteQueries {
    queries: Vec<BranchExactDualWriteQuery>,
}

impl BranchExactDualWriteQueries {
    pub fn new(keyspace: &CqlKeyspaceName) -> Self {
        let target = BranchExactQueries::new(keyspace);
        let keyspace = keyspace.as_str();
        let legacy_c2p = format!("{keyspace}.checkpoint_id_to_pending_id_table");
        let legacy_p2c = format!("{keyspace}.pending_id_to_checkpoint_id_table");
        let legacy_p2proc =
            format!("{keyspace}.pending_id_to_pending_proc_id_table_u64_to_u128");
        let legacy_proc2p =
            format!("{keyspace}.pending_id_to_pending_proc_id_table_u128_to_u64");
        let legacy_proof = format!("{keyspace}.checkpointed_object_table");
        let query = |id, cql, bind_shape| BranchExactDualWriteQuery {
            id,
            cql,
            bind_shape,
        };
        Self {
            queries: vec![
                query(BranchExactDualWriteQueryId::LegacyCheckpointToPendingPut, format!("INSERT INTO {legacy_c2p} (obj_id, value) VALUES (?, ?) USING TIMESTAMP ?"), &["BIGINT", "BIGINT", "BIGINT"]),
                query(BranchExactDualWriteQueryId::LegacyCheckpointToPendingRead, format!("SELECT value, writetime(value) FROM {legacy_c2p} WHERE obj_id = ?"), &["BIGINT"]),
                query(BranchExactDualWriteQueryId::LegacyPendingToCheckpointPut, format!("INSERT INTO {legacy_p2c} (obj_id, value) VALUES (?, ?) USING TIMESTAMP ?"), &["BIGINT", "BIGINT", "BIGINT"]),
                query(BranchExactDualWriteQueryId::LegacyPendingToCheckpointRead, format!("SELECT value, writetime(value) FROM {legacy_p2c} WHERE obj_id = ?"), &["BIGINT"]),
                query(BranchExactDualWriteQueryId::LegacyPendingToProcPut, format!("INSERT INTO {legacy_p2proc} (obj_id, value) VALUES (?, ?) USING TIMESTAMP ?"), &["BIGINT", "UUID", "BIGINT"]),
                query(BranchExactDualWriteQueryId::LegacyPendingToProcRead, format!("SELECT value, writetime(value) FROM {legacy_p2proc} WHERE obj_id = ?"), &["BIGINT"]),
                query(BranchExactDualWriteQueryId::LegacyProcToPendingPut, format!("INSERT INTO {legacy_proc2p} (obj_id, value) VALUES (?, ?) USING TIMESTAMP ?"), &["UUID", "BIGINT", "BIGINT"]),
                query(BranchExactDualWriteQueryId::LegacyProcToPendingRead, format!("SELECT value, writetime(value) FROM {legacy_proc2p} WHERE obj_id = ?"), &["UUID"]),
                query(BranchExactDualWriteQueryId::LegacyPendingRewardProofPut, format!("INSERT INTO {legacy_proof} (obj_id, checkpoint_id, value) VALUES (?, ?, ?) USING TIMESTAMP ?"), &["BIGINT", "BIGINT", "BLOB", "BIGINT"]),
                query(BranchExactDualWriteQueryId::LegacyPendingRewardProofRead, format!("SELECT value, writetime(value) FROM {legacy_proof} WHERE obj_id = ? AND checkpoint_id = ?"), &["BIGINT", "BIGINT"]),
                query(BranchExactDualWriteQueryId::TargetBranchToPendingPut, target.get(BranchExactQueryId::PutBranchToPending).cql().to_owned(), &["BLOB", "BIGINT", "BLOB", "BIGINT"]),
                query(BranchExactDualWriteQueryId::TargetBranchToPendingRead, target.get(BranchExactQueryId::ReadBranchToPending).cql().to_owned(), &["BLOB"]),
                query(BranchExactDualWriteQueryId::TargetPendingToBranchPut, target.get(BranchExactQueryId::PutPendingToBranch).cql().to_owned(), &["BIGINT", "BLOB", "BLOB", "BIGINT"]),
                query(BranchExactDualWriteQueryId::TargetPendingToBranchRead, target.get(BranchExactQueryId::ReadPendingToBranch).cql().to_owned(), &["BIGINT"]),
                query(BranchExactDualWriteQueryId::TargetPendingRewardProofPut, target.get(BranchExactQueryId::PutPendingRewardProof).cql().to_owned(), &["BIGINT", "BLOB", "BIGINT"]),
                query(BranchExactDualWriteQueryId::TargetPendingRewardProofRead, format!("SELECT value, writetime(value) FROM {keyspace}.pending_reward_top_proof_table WHERE pending_id = ?"), &["BIGINT"]),
            ],
        }
    }

    pub fn get(&self, id: BranchExactDualWriteQueryId) -> &BranchExactDualWriteQuery {
        &self.queries[id as usize - 1]
    }

    pub fn golden(&self) -> String {
        self.queries
            .iter()
            .map(|query| {
                format!(
                    "{:?}\n{}\n{}\n",
                    query.id,
                    query.cql,
                    query.bind_shape.join(",")
                )
            })
            .collect()
    }
}

struct PreparedDualWrite {
    statements: Vec<Option<PreparedStatement>>,
}

impl PreparedDualWrite {
    fn get(
        &self,
        id: BranchExactDualWriteQueryId,
    ) -> Result<&PreparedStatement, BranchExactDualWriteExecutionError> {
        self.statements[id as usize - 1]
            .as_ref()
            .ok_or(BranchExactDualWriteExecutionError::QueryUnavailableForAuthority(id))
    }
}

const fn realm_only_query(id: BranchExactDualWriteQueryId) -> bool {
    matches!(
        id,
        BranchExactDualWriteQueryId::LegacyPendingRewardProofPut
            | BranchExactDualWriteQueryId::LegacyPendingRewardProofRead
            | BranchExactDualWriteQueryId::TargetPendingRewardProofPut
            | BranchExactDualWriteQueryId::TargetPendingRewardProofRead
    )
}

/// Verified row evidence.  Its constructor is private to this executor
/// module, so h22b cannot be advanced by an arbitrary non-zero digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BranchExactVerifiedWriteObservation {
    prepared_digest: [u8; 32],
    intent_digest: BranchExactDualWriteIntentDigest,
    timestamp: CommitWriteTimestampUs,
    timestamp_revision: u64,
    row_digests: Vec<[u8; 32]>,
    digest: [u8; 32],
}

impl BranchExactVerifiedWriteObservation {
    pub(crate) const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(crate) fn matches_prepared<Hash: Q256BitHash>(
        &self,
        prepared: &super::BranchExactWriterPrepared<Hash>,
    ) -> bool {
        self.prepared_digest == *prepared.digest()
            && self.intent_digest == prepared.intent().intent_digest()
            && self.timestamp == prepared.timestamp()
            && self.timestamp_revision == prepared.timestamp_revision().get()
            && self.row_digests.len() == prepared.intent().mutations().len()
    }

    #[cfg(test)]
    pub(crate) fn test_fixture<Hash: Q256BitHash>(
        prepared: &super::BranchExactWriterPrepared<Hash>,
    ) -> Self {
        let rows = prepared
            .intent()
            .mutations()
            .iter()
            .map(|mutation| *mutation.digest().as_bytes())
            .collect::<Vec<_>>();
        build_observation(prepared, rows)
    }
}

#[derive(Clone, Debug)]
struct ExecutableRows {
    checkpoint: i64,
    pending: i64,
    proc_id: Uuid,
    canonical_ref: Vec<u8>,
    mapping_digest: Vec<u8>,
    proof: Option<Vec<u8>>,
    timestamp: i64,
}

impl ExecutableRows {
    fn try_from_sealed<Hash: Q256BitHash>(
        sealed: &SealedBranchExactDualWrite<Hash>,
    ) -> Result<Self, BranchExactDualWriteExecutionError> {
        Self::try_from_inventory(sealed.intent(), sealed.write_timestamp())
    }

    fn try_from_inventory<Hash: Q256BitHash>(
        intent: &BranchExactDualWriteIntent<Hash>,
        timestamp: CommitWriteTimestampUs,
    ) -> Result<Self, BranchExactDualWriteExecutionError> {
        let checkpoint_u64 = intent
            .candidate()
            .canonical_chain()
            .checkpoint()
            .checkpoint_id()
            .get();
        let checkpoint = i64::try_from(checkpoint_u64).map_err(|_| {
            BranchExactDualWriteExecutionError::CheckpointOutOfRange(checkpoint_u64)
        })?;
        let pending = i64::try_from(intent.candidate().pending_id().get())
            .expect("UniquePendingId is bounded by i64::MAX");
        let mapping_digest = intent.candidate().digest().as_bytes().to_vec();
        Ok(Self {
            checkpoint,
            pending,
            proc_id: Uuid::from_u128(intent.proc_checkpoint_id().as_u128()),
            canonical_ref: intent.candidate().canonical_chain_bytes().to_vec(),
            mapping_digest,
            // Raw canonical bytes are intentionally the physical value for
            // online writes. Existing readers accept raw or PSZ1-compressed
            // values; raw bytes make same-timestamp crash retry byte-exact
            // across compression-library upgrades.
            proof: intent.reward_proof_canonical().map(ToOwned::to_owned),
            timestamp: timestamp.as_i64(),
        })
    }

    fn mutation_count(&self) -> usize {
        if self.proof.is_some() { 8 } else { 6 }
    }
}

/// Exact physical observation for one narrow Realm inventory leg. Both the
/// logical value and the stored bytes are retained because target mapping
/// rows carry a separate mapping digest, while proof rows may be compressed.
/// This value is archive input only and grants no write or delete authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RealmRollbackNarrowObservedRow {
    kind: BranchExactDualWriteMutationKind,
    primary_key: Vec<u8>,
    logical_value: Vec<u8>,
    stored_value: Vec<u8>,
    writetime_us: i64,
}

impl RealmRollbackNarrowObservedRow {
    pub(crate) const fn kind(&self) -> BranchExactDualWriteMutationKind {
        self.kind
    }

    pub(crate) fn primary_key(&self) -> &[u8] { &self.primary_key }

    pub(crate) fn logical_value(&self) -> &[u8] { &self.logical_value }

    pub(crate) fn stored_value(&self) -> &[u8] { &self.stored_value }

    pub(crate) const fn writetime_us(&self) -> i64 { self.writetime_us }
}

pub(crate) struct ScyllaBranchExactDualWriteAdapter {
    session: Arc<Session>,
    ready_digest: BranchExactSchemaReadyDigest,
    authority: AuthorityScope,
    queries: BranchExactDualWriteQueries,
    prepared: PreparedDualWrite,
}

impl ScyllaBranchExactDualWriteAdapter {
    pub(crate) async fn prepare(
        session: Arc<Session>,
        ready: &BranchExactSchemaReady,
    ) -> Result<Self, BranchExactDualWriteExecutionError> {
        let view = ready.view();
        let queries = BranchExactDualWriteQueries::new(view.keyspace());
        let mut statements = Vec::with_capacity(16);
        for query in &queries.queries {
            if view.authority() == AuthorityScope::Coordinator
                && realm_only_query(query.id())
            {
                statements.push(None);
                continue;
            }
            let mut prepared = session
                .prepare(query.cql())
                .await
                .map_err(driver)?;
            prepared.set_consistency(Consistency::Quorum);
            prepared.set_is_idempotent(true);
            statements.push(Some(prepared));
        }
        Ok(Self {
            session,
            ready_digest: view.digest(),
            authority: view.authority(),
            queries,
            prepared: PreparedDualWrite { statements },
        })
    }

    pub(crate) const fn queries(&self) -> &BranchExactDualWriteQueries {
        &self.queries
    }

    /// Read every physical leg retained by one committed Realm inventory and
    /// require the exact logical value, stored representation, and sealed
    /// writetime. This is a read-only archive seam; it cannot execute or seal
    /// the original mutation.
    pub(crate) async fn read_inventory_exact<Hash: Q256BitHash>(
        &self,
        intent: &BranchExactDualWriteIntent<Hash>,
        timestamp: CommitWriteTimestampUs,
    ) -> Result<Vec<RealmRollbackNarrowObservedRow>, BranchExactDualWriteExecutionError> {
        if intent.authority() != self.authority {
            return Err(BranchExactDualWriteExecutionError::AuthorityMismatch);
        }
        let expected = ExecutableRows::try_from_inventory(intent, timestamp)?;
        let observed = self.read_all(&expected).await?;
        if observed.len() != intent.mutations().len() {
            return Err(BranchExactDualWriteExecutionError::InventoryRowCountMismatch {
                expected: intent.mutations().len(),
                actual: observed.len(),
            });
        }
        let mut exact = Vec::with_capacity(observed.len());
        for (index, (mutation, row)) in intent
            .mutations()
            .iter()
            .zip(observed)
            .enumerate()
        {
            let row = row.ok_or_else(|| {
                BranchExactDualWriteExecutionError::MissingRows(vec![index])
            })?;
            if row.kind != mutation.kind() {
                return Err(BranchExactDualWriteExecutionError::InventoryKindMismatch {
                    expected: mutation.kind(),
                    actual: row.kind,
                });
            }
            if row.require_postwrite()? != RowPostwrite::Verified {
                return Err(BranchExactDualWriteExecutionError::InventoryRowNotExact(
                    row.kind,
                ));
            }
            exact.push(RealmRollbackNarrowObservedRow {
                kind: row.kind,
                primary_key: row.key,
                logical_value: row.logical,
                stored_value: row.stored,
                writetime_us: row.writetime,
            });
        }
        Ok(exact)
    }

    async fn execute<Hash: Q256BitHash>(
        &self,
        prepared: &super::BranchExactWriterPrepared<Hash>,
        sealed: &SealedBranchExactDualWrite<Hash>,
    ) -> Result<BranchExactVerifiedWriteObservation, BranchExactDualWriteExecutionError> {
        self.execute_with_limit(prepared, sealed, usize::MAX).await
    }

    async fn execute_with_limit<Hash: Q256BitHash>(
        &self,
        prepared: &super::BranchExactWriterPrepared<Hash>,
        sealed: &SealedBranchExactDualWrite<Hash>,
        limit: usize,
    ) -> Result<BranchExactVerifiedWriteObservation, BranchExactDualWriteExecutionError> {
        if sealed.intent().authority() != self.authority {
            return Err(BranchExactDualWriteExecutionError::AuthorityMismatch);
        }
        let rows = ExecutableRows::try_from_sealed(sealed)?;
        self.preflight(&rows).await?;
        let count = rows.mutation_count();
        let mut failures = Vec::new();
        for index in 0..count.min(limit) {
            if let Err(error) = self.execute_one(index, &rows).await {
                failures.push((index, error.to_string()));
            }
        }
        if limit < count {
            return Err(BranchExactDualWriteExecutionError::InjectedCrash {
                completed: limit,
                total: count,
            });
        }
        match self.verify_all(prepared, &rows).await {
            Ok(observation) => Ok(observation),
            Err(BranchExactDualWriteExecutionError::MissingRows(missing)) => {
                Err(BranchExactDualWriteExecutionError::RetryablePartial {
                    missing,
                    write_failures: failures,
                })
            }
            Err(error) => Err(error),
        }
    }

    async fn execute_one(
        &self,
        index: usize,
        rows: &ExecutableRows,
    ) -> Result<(), BranchExactDualWriteExecutionError> {
        use BranchExactDualWriteQueryId as Q;
        let ts = rows.timestamp;
        match index {
            0 => self.session.execute_unpaged(self.prepared.get(Q::LegacyCheckpointToPendingPut)?, (rows.checkpoint, rows.pending, ts)).await,
            1 => self.session.execute_unpaged(self.prepared.get(Q::LegacyPendingToCheckpointPut)?, (rows.pending, rows.checkpoint, ts)).await,
            2 => self.session.execute_unpaged(self.prepared.get(Q::LegacyPendingToProcPut)?, (rows.pending, rows.proc_id, ts)).await,
            3 => self.session.execute_unpaged(self.prepared.get(Q::LegacyProcToPendingPut)?, (rows.proc_id, rows.pending, ts)).await,
            4 => self.session.execute_unpaged(self.prepared.get(Q::TargetBranchToPendingPut)?, (rows.canonical_ref.as_slice(), rows.pending, rows.mapping_digest.as_slice(), ts)).await,
            5 => self.session.execute_unpaged(self.prepared.get(Q::TargetPendingToBranchPut)?, (rows.pending, rows.canonical_ref.as_slice(), rows.mapping_digest.as_slice(), ts)).await,
            6 => self.session.execute_unpaged(self.prepared.get(Q::LegacyPendingRewardProofPut)?, (LEGACY_REWARD_PROOF_OBJ_ID, rows.pending, rows.proof.as_deref().ok_or(BranchExactDualWriteExecutionError::MissingRealmProof)?, ts)).await,
            7 => self.session.execute_unpaged(self.prepared.get(Q::TargetPendingRewardProofPut)?, (rows.pending, rows.proof.as_deref().ok_or(BranchExactDualWriteExecutionError::MissingRealmProof)?, ts)).await,
            _ => return Err(BranchExactDualWriteExecutionError::MutationIndex(index)),
        }
        .map_err(driver)?;
        Ok(())
    }

    async fn preflight(
        &self,
        rows: &ExecutableRows,
    ) -> Result<(), BranchExactDualWriteExecutionError> {
        let observed = self.read_all(rows).await?;
        for row in observed {
            if let Some(row) = row {
                row.require_preflight()?;
            }
        }
        Ok(())
    }

    async fn verify_all<Hash: Q256BitHash>(
        &self,
        prepared: &super::BranchExactWriterPrepared<Hash>,
        rows: &ExecutableRows,
    ) -> Result<BranchExactVerifiedWriteObservation, BranchExactDualWriteExecutionError> {
        let observed = self.read_all(rows).await?;
        let mut missing = Vec::new();
        let mut digests = Vec::with_capacity(rows.mutation_count());
        for (index, observed) in observed.into_iter().enumerate() {
            match observed {
                None => missing.push(index),
                Some(row) => {
                    match row.require_postwrite()? {
                        RowPostwrite::Verified => digests.push(row.digest()),
                        RowPostwrite::RetryableStaleTimestamp => {
                            missing.push(index)
                        }
                    }
                }
            }
        }
        if !missing.is_empty() {
            return Err(BranchExactDualWriteExecutionError::MissingRows(missing));
        }
        Ok(build_observation(prepared, digests))
    }

    async fn read_all(
        &self,
        expected: &ExecutableRows,
    ) -> Result<Vec<Option<ObservedPhysicalRow>>, BranchExactDualWriteExecutionError> {
        use BranchExactDualWriteMutationKind as K;
        use BranchExactDualWriteQueryId as Q;
        let mut rows = Vec::with_capacity(expected.mutation_count());
        rows.push(self.read_i64(Q::LegacyCheckpointToPendingRead, (expected.checkpoint,), K::LegacyCheckpointToPending, expected.checkpoint.to_be_bytes().to_vec(), expected.pending, expected.timestamp).await?);
        rows.push(self.read_i64(Q::LegacyPendingToCheckpointRead, (expected.pending,), K::LegacyPendingToCheckpoint, expected.pending.to_be_bytes().to_vec(), expected.checkpoint, expected.timestamp).await?);
        rows.push(self.read_uuid(Q::LegacyPendingToProcRead, (expected.pending,), K::LegacyPendingToProc, expected.pending.to_be_bytes().to_vec(), expected.proc_id, expected.timestamp).await?);
        rows.push(self.read_i64_uuid_key(Q::LegacyProcToPendingRead, (expected.proc_id,), K::LegacyProcToPending, expected.proc_id.as_bytes().to_vec(), expected.pending, expected.timestamp).await?);
        rows.push(self.read_target_forward(expected).await?);
        rows.push(self.read_target_reverse(expected).await?);
        if let Some(proof) = &expected.proof {
            rows.push(self.read_blob(Q::LegacyPendingRewardProofRead, (LEGACY_REWARD_PROOF_OBJ_ID, expected.pending), K::LegacyPendingRewardProof, [LEGACY_REWARD_PROOF_OBJ_ID.to_be_bytes().as_slice(), expected.pending.to_be_bytes().as_slice()].concat(), proof, expected.timestamp).await?);
            rows.push(self.read_blob_one(Q::TargetPendingRewardProofRead, (expected.pending,), K::TargetPendingRewardProof, expected.pending.to_be_bytes().to_vec(), proof, expected.timestamp).await?);
        }
        Ok(rows)
    }

    async fn read_i64<V: scylla::serialize::row::SerializeRow>(
        &self, query: BranchExactDualWriteQueryId, bind: V,
        kind: BranchExactDualWriteMutationKind, key: Vec<u8>, expected: i64, ts: i64,
    ) -> Result<Option<ObservedPhysicalRow>, BranchExactDualWriteExecutionError> {
        let row = self.session.execute_unpaged(self.prepared.get(query)?, bind).await.map_err(driver)?.into_rows_result().map_err(driver)?.maybe_first_row::<(Option<i64>, Option<i64>)>().map_err(driver)?;
        row.map(|(value, writetime)| {
            let value = value.ok_or(BranchExactDualWriteExecutionError::NullCell(kind))?;
            let writetime = writetime.ok_or(BranchExactDualWriteExecutionError::NullCell(kind))?;
            Ok(ObservedPhysicalRow::new(kind, key, expected.to_be_bytes().to_vec(), value.to_be_bytes().to_vec(), value.to_be_bytes().to_vec(), writetime, ts))
        }).transpose()
    }

    async fn read_i64_uuid_key<V: scylla::serialize::row::SerializeRow>(
        &self, query: BranchExactDualWriteQueryId, bind: V,
        kind: BranchExactDualWriteMutationKind, key: Vec<u8>, expected: i64, ts: i64,
    ) -> Result<Option<ObservedPhysicalRow>, BranchExactDualWriteExecutionError> {
        self.read_i64(query, bind, kind, key, expected, ts).await
    }

    async fn read_uuid<V: scylla::serialize::row::SerializeRow>(
        &self, query: BranchExactDualWriteQueryId, bind: V,
        kind: BranchExactDualWriteMutationKind, key: Vec<u8>, expected: Uuid, ts: i64,
    ) -> Result<Option<ObservedPhysicalRow>, BranchExactDualWriteExecutionError> {
        let row = self.session.execute_unpaged(self.prepared.get(query)?, bind).await.map_err(driver)?.into_rows_result().map_err(driver)?.maybe_first_row::<(Option<Uuid>, Option<i64>)>().map_err(driver)?;
        row.map(|(value, writetime)| {
            let value = value.ok_or(BranchExactDualWriteExecutionError::NullCell(kind))?;
            let writetime = writetime.ok_or(BranchExactDualWriteExecutionError::NullCell(kind))?;
            Ok(ObservedPhysicalRow::new(kind, key, expected.as_bytes().to_vec(), value.as_bytes().to_vec(), value.as_bytes().to_vec(), writetime, ts))
        }).transpose()
    }

    async fn read_blob<V: scylla::serialize::row::SerializeRow>(
        &self, query: BranchExactDualWriteQueryId, bind: V,
        kind: BranchExactDualWriteMutationKind, key: Vec<u8>, expected: &[u8], ts: i64,
    ) -> Result<Option<ObservedPhysicalRow>, BranchExactDualWriteExecutionError> {
        self.read_blob_one(query, bind, kind, key, expected, ts).await
    }

    async fn read_blob_one<V: scylla::serialize::row::SerializeRow>(
        &self, query: BranchExactDualWriteQueryId, bind: V,
        kind: BranchExactDualWriteMutationKind, key: Vec<u8>, expected: &[u8], ts: i64,
    ) -> Result<Option<ObservedPhysicalRow>, BranchExactDualWriteExecutionError> {
        let row = self.session.execute_unpaged(self.prepared.get(query)?, bind).await.map_err(driver)?.into_rows_result().map_err(driver)?.maybe_first_row::<(Option<Vec<u8>>, Option<i64>)>().map_err(driver)?;
        row.map(|(stored, writetime)| {
            let stored = stored.ok_or(BranchExactDualWriteExecutionError::NullCell(kind))?;
            let writetime = writetime.ok_or(BranchExactDualWriteExecutionError::NullCell(kind))?;
            let logical = crate::compression::decompress(&stored).map_err(|error| BranchExactDualWriteExecutionError::MalformedProof(error.to_string()))?;
            Ok(ObservedPhysicalRow::new(kind, key, expected.to_vec(), logical, stored, writetime, ts))
        }).transpose()
    }

    async fn read_target_forward(&self, expected: &ExecutableRows) -> Result<Option<ObservedPhysicalRow>, BranchExactDualWriteExecutionError> {
        let rows = self.session.execute_unpaged(self.prepared.get(BranchExactDualWriteQueryId::TargetBranchToPendingRead)?, (expected.canonical_ref.as_slice(),)).await.map_err(driver)?.into_rows_result().map_err(driver)?;
        let values = rows.rows::<(i64, Vec<u8>, i64)>().map_err(driver)?.collect::<Result<Vec<_>, _>>().map_err(driver)?;
        target_mapping_row(BranchExactDualWriteMutationKind::TargetBranchToPending, expected.canonical_ref.clone(), expected.pending.to_be_bytes().to_vec(), expected.mapping_digest.as_slice(), expected.timestamp, values.into_iter().map(|(pending,digest,ts)| (pending.to_be_bytes().to_vec(),digest,ts)).collect())
    }

    async fn read_target_reverse(&self, expected: &ExecutableRows) -> Result<Option<ObservedPhysicalRow>, BranchExactDualWriteExecutionError> {
        let rows = self.session.execute_unpaged(self.prepared.get(BranchExactDualWriteQueryId::TargetPendingToBranchRead)?, (expected.pending,)).await.map_err(driver)?.into_rows_result().map_err(driver)?;
        let values = rows.rows::<(Vec<u8>, Vec<u8>, i64)>().map_err(driver)?.collect::<Result<Vec<_>, _>>().map_err(driver)?;
        target_mapping_row(BranchExactDualWriteMutationKind::TargetPendingToBranch, expected.pending.to_be_bytes().to_vec(), expected.canonical_ref.clone(), expected.mapping_digest.as_slice(), expected.timestamp, values)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedPhysicalRow {
    kind: BranchExactDualWriteMutationKind,
    key: Vec<u8>,
    expected_logical: Vec<u8>,
    logical: Vec<u8>,
    stored: Vec<u8>,
    writetime: i64,
    expected_writetime: i64,
}

impl ObservedPhysicalRow {
    fn new(kind: BranchExactDualWriteMutationKind, key: Vec<u8>, expected_logical: Vec<u8>, logical: Vec<u8>, stored: Vec<u8>, writetime: i64, expected_writetime: i64) -> Self {
        Self { kind, key, expected_logical, logical, stored, writetime, expected_writetime }
    }

    fn require_logical_match(&self) -> Result<(), BranchExactDualWriteExecutionError> {
        if self.logical != self.expected_logical {
            return Err(BranchExactDualWriteExecutionError::ConflictingRow(self.kind));
        }
        Ok(())
    }

    fn require_preflight(&self) -> Result<(), BranchExactDualWriteExecutionError> {
        self.require_logical_match()?;
        match self.writetime.cmp(&self.expected_writetime) {
            Ordering::Greater => Err(
                BranchExactDualWriteExecutionError::SealedTimestampSuperseded {
                    kind: self.kind,
                    sealed: self.expected_writetime,
                    actual: self.writetime,
                },
            ),
            Ordering::Equal => self.require_exact_physical_value(),
            Ordering::Less => Ok(()),
        }
    }

    fn require_postwrite(
        &self,
    ) -> Result<RowPostwrite, BranchExactDualWriteExecutionError> {
        self.require_logical_match()?;
        match self.writetime.cmp(&self.expected_writetime) {
            Ordering::Less => Ok(RowPostwrite::RetryableStaleTimestamp),
            Ordering::Equal => {
                self.require_exact_physical_value()?;
                Ok(RowPostwrite::Verified)
            }
            Ordering::Greater => Err(
                BranchExactDualWriteExecutionError::SealedTimestampSuperseded {
                    kind: self.kind,
                    sealed: self.expected_writetime,
                    actual: self.writetime,
                },
            ),
        }
    }

    fn require_exact_physical_value(
        &self,
    ) -> Result<(), BranchExactDualWriteExecutionError> {
        if matches!(self.kind, BranchExactDualWriteMutationKind::LegacyPendingRewardProof | BranchExactDualWriteMutationKind::TargetPendingRewardProof) && self.stored != self.expected_logical {
            return Err(BranchExactDualWriteExecutionError::PhysicalProofMismatch(self.kind));
        }
        Ok(())
    }

    fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(ROW_OBSERVATION_DOMAIN);
        hasher.update([self.kind as u8]);
        update_len(&mut hasher, &self.key);
        update_len(&mut hasher, &self.logical);
        update_len(&mut hasher, &self.stored);
        hasher.update(self.writetime.to_be_bytes());
        hasher.finalize().into()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RowPostwrite {
    Verified,
    RetryableStaleTimestamp,
}

fn target_mapping_row(
    kind: BranchExactDualWriteMutationKind,
    key: Vec<u8>,
    expected_value: Vec<u8>,
    expected_digest: &[u8],
    expected_ts: i64,
    rows: Vec<(Vec<u8>, Vec<u8>, i64)>,
) -> Result<Option<ObservedPhysicalRow>, BranchExactDualWriteExecutionError> {
    match rows.as_slice() {
        [] => Ok(None),
        [(value, digest, writetime)] if digest.as_slice() == expected_digest => {
            Ok(Some(ObservedPhysicalRow::new(kind, key, expected_value, value.clone(), digest.clone(), *writetime, expected_ts)))
        }
        _ => Err(BranchExactDualWriteExecutionError::TargetCardinalityOrDigest { kind, rows: rows.len() }),
    }
}

fn build_observation<Hash: Q256BitHash>(
    prepared: &super::BranchExactWriterPrepared<Hash>,
    row_digests: Vec<[u8; 32]>,
) -> BranchExactVerifiedWriteObservation {
    let mut hasher = Sha256::new();
    hasher.update(OBSERVATION_DOMAIN);
    hasher.update(prepared.digest());
    hasher.update(prepared.intent().intent_digest().as_bytes());
    hasher.update(prepared.timestamp_revision().get().to_be_bytes());
    hasher.update(prepared.timestamp().as_i64().to_be_bytes());
    hasher.update((row_digests.len() as u64).to_be_bytes());
    for digest in &row_digests {
        hasher.update(digest);
    }
    BranchExactVerifiedWriteObservation {
        prepared_digest: *prepared.digest(),
        intent_digest: prepared.intent().intent_digest(),
        timestamp: prepared.timestamp(),
        timestamp_revision: prepared.timestamp_revision().get(),
        row_digests,
        digest: hasher.finalize().into(),
    }
}

fn update_len(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

pub(crate) struct ScyllaBranchExactDualWriteExecutor;

impl ScyllaBranchExactDualWriteExecutor {
    pub(crate) async fn run<Hash: Q256BitHash>(
        writer: &ScyllaBranchExactWriterLifecycleStore,
        timestamps: &ScyllaAuthorityTimestampStore,
        adapter: &ScyllaBranchExactDualWriteAdapter,
        key: super::BranchExactWriterAuthorityKey,
    ) -> Result<StoredBranchExactWriterLifecycle<Hash>, BranchExactDualWriteExecutionError> {
        let super::BranchExactWriterReadState::Current(current) = writer.read(key).await.map_err(store)? else {
            return Err(BranchExactDualWriteExecutionError::WriterUninitialized);
        };
        if current.plan().schema_ready_digest() != adapter.ready_digest || current.plan().authority() != adapter.authority {
            return Err(BranchExactDualWriteExecutionError::ReadyTokenMismatch);
        }
        match current.state() {
            BranchExactWriterState::WritePrepared(prepared) => {
                let timestamp_key = AuthorityTimestampKey::new(
                    prepared
                        .intent()
                        .candidate()
                        .canonical_chain()
                        .network_id(),
                    prepared.intent().authority(),
                );
                let timestamp_state = timestamps
                    .read_observed(timestamp_key)
                    .await
                    .map_err(timestamp_store_error)?
                    .ok_or(BranchExactDualWriteExecutionError::TimestampStateUninitialized)?;
                let sealed = prepared.reseal(timestamp_state).map_err(lifecycle)?;
                let observation = adapter.execute(prepared, &sealed).await?;
                let cas = SealedBranchExactWriterCas::verify_writes(&current, &observation).map_err(lifecycle)?;
                match writer.compare_and_set(&cas).await.map_err(store)? {
                    BranchExactWriterWriteOutcome::Applied(next) | BranchExactWriterWriteOutcome::Idempotent(next) => Ok(next),
                    BranchExactWriterWriteOutcome::Conflict(next) => match next.state() {
                        BranchExactWriterState::WritesVerified(verified) if verified.prepared().digest() == prepared.digest() && verified.observation().as_bytes() == &observation.digest() => Ok(next),
                        _ => Err(BranchExactDualWriteExecutionError::LifecycleConflict),
                    },
                }
            }
            BranchExactWriterState::WritesVerified(_) => Ok(current),
            _ => Err(BranchExactDualWriteExecutionError::WriterNotPrepared),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactDualWriteExecutionError {
    Driver(String),
    Store(String),
    Lifecycle(String),
    AuthorityMismatch,
    ReadyTokenMismatch,
    WriterUninitialized,
    WriterNotPrepared,
    LifecycleConflict,
    CheckpointOutOfRange(u64),
    MutationIndex(usize),
    QueryUnavailableForAuthority(BranchExactDualWriteQueryId),
    MissingRealmProof,
    TimestampStateUninitialized,
    NullCell(BranchExactDualWriteMutationKind),
    ConflictingRow(BranchExactDualWriteMutationKind),
    TargetCardinalityOrDigest { kind: BranchExactDualWriteMutationKind, rows: usize },
    SealedTimestampSuperseded { kind: BranchExactDualWriteMutationKind, sealed: i64, actual: i64 },
    PhysicalProofMismatch(BranchExactDualWriteMutationKind),
    MalformedProof(String),
    InventoryRowCountMismatch { expected: usize, actual: usize },
    InventoryKindMismatch {
        expected: BranchExactDualWriteMutationKind,
        actual: BranchExactDualWriteMutationKind,
    },
    InventoryRowNotExact(BranchExactDualWriteMutationKind),
    MissingRows(Vec<usize>),
    RetryablePartial { missing: Vec<usize>, write_failures: Vec<(usize, String)> },
    InjectedCrash { completed: usize, total: usize },
}

impl fmt::Display for BranchExactDualWriteExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { write!(formatter, "{self:?}") }
}
impl Error for BranchExactDualWriteExecutionError {}

fn driver(error: impl fmt::Display) -> BranchExactDualWriteExecutionError { BranchExactDualWriteExecutionError::Driver(error.to_string()) }
fn store(error: impl fmt::Display) -> BranchExactDualWriteExecutionError { BranchExactDualWriteExecutionError::Store(error.to_string()) }
fn timestamp_store_error(error: impl fmt::Display) -> BranchExactDualWriteExecutionError { BranchExactDualWriteExecutionError::Store(error.to_string()) }
fn lifecycle(error: BranchExactWriterLifecycleError) -> BranchExactDualWriteExecutionError { BranchExactDualWriteExecutionError::Lifecycle(error.to_string()) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_golden_requires_timestamp_and_writetime_for_every_leg() {
        let keyspace = CqlKeyspaceName::try_new("psy_h22").unwrap();
        let queries = BranchExactDualWriteQueries::new(&keyspace);
        let golden = queries.golden();
        assert_eq!(queries.queries.len(), 16);
        for (index, query) in queries.queries.iter().enumerate() {
            assert_eq!(query.id() as usize, index + 1);
        }
        assert_eq!(golden.matches("USING TIMESTAMP ?").count(), 8);
        assert_eq!(golden.matches("writetime(").count(), 8);
        assert!(golden.contains("mapping_digest"));
        assert!(golden.contains("checkpoint_id = ?"));
        assert!(!golden.contains("checkpoint_id <= ?"));
        assert!(!golden.contains("DELETE"));
    }

    #[test]
    fn proof_queries_are_realm_only_and_prototype_is_not_wired() {
        use BranchExactDualWriteQueryId as Q;
        let realm_only = [
            Q::LegacyPendingRewardProofPut,
            Q::LegacyPendingRewardProofRead,
            Q::TargetPendingRewardProofPut,
            Q::TargetPendingRewardProofRead,
        ];
        for id in BranchExactDualWriteQueries::new(
            &CqlKeyspaceName::try_new("psy_h22").unwrap(),
        )
        .queries
        .iter()
        .map(BranchExactDualWriteQuery::id)
        {
            assert_eq!(realm_only_query(id), realm_only.contains(&id));
        }
        let setup = include_str!("../psy_setup.rs");
        assert!(!setup.contains("ScyllaBranchExactDualWriteAdapter"));
        assert!(!setup.contains("ScyllaBranchExactDualWriteExecutor"));
    }

    #[test]
    fn target_mapping_preflight_detects_extra_or_wrong_digest() {
        let kind = BranchExactDualWriteMutationKind::TargetBranchToPending;
        assert!(target_mapping_row(kind, vec![1], vec![2], &[3; 32], 7, vec![]).unwrap().is_none());
        assert!(matches!(target_mapping_row(kind, vec![1], vec![2], &[3; 32], 7, vec![(vec![2], vec![4; 32], 7)]), Err(BranchExactDualWriteExecutionError::TargetCardinalityOrDigest { .. })));
        assert!(matches!(target_mapping_row(kind, vec![1], vec![2], &[3; 32], 7, vec![(vec![2], vec![3; 32], 7), (vec![9], vec![3; 32], 7)]), Err(BranchExactDualWriteExecutionError::TargetCardinalityOrDigest { rows: 2, .. })));

        let stale = target_mapping_row(
            kind,
            vec![1],
            vec![2],
            &[3; 32],
            7,
            vec![(vec![2], vec![3; 32], 6)],
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            stale.require_postwrite().unwrap(),
            RowPostwrite::RetryableStaleTimestamp
        );
    }

    #[test]
    fn postread_requires_exact_timestamp_and_raw_proof_bytes() {
        let kind = BranchExactDualWriteMutationKind::LegacyPendingRewardProof;
        let row = ObservedPhysicalRow::new(kind, vec![1], vec![2], vec![2], vec![2], 10, 11);
        assert_eq!(
            row.require_postwrite().unwrap(),
            RowPostwrite::RetryableStaleTimestamp
        );
        let row = ObservedPhysicalRow::new(kind, vec![1], vec![2], vec![2], vec![2], 12, 11);
        assert!(matches!(
            row.require_preflight(),
            Err(BranchExactDualWriteExecutionError::SealedTimestampSuperseded { .. })
        ));
        let row = ObservedPhysicalRow::new(kind, vec![1], vec![2], vec![2], vec![9], 11, 11);
        assert_eq!(row.require_postwrite(), Err(BranchExactDualWriteExecutionError::PhysicalProofMismatch(kind)));
    }
}
