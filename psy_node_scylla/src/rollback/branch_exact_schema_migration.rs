//! Isolated schema-migration prototype for the two Realm commit blockers.
//!
//! This module is intentionally absent from `psy_setup.rs` and every current
//! writer.  It proves the target shape for replacing the reusable-height
//! pending mapping and for removing pending-keyed reward proofs from the
//! mixed-axis `checkpointed_object_table`.

use std::{error::Error, fmt};

use parth_core::{
    crypto::hash::tag_tree::TagTreeMerkleProof,
    protocol::core_types::Q256BitHash,
};
use psy_node_core::store::{
    branch_pending_mapping::{
        BranchPendingMapping, BranchPendingMappingDigest,
    },
    timestamp::CommitWriteTimestampUs,
    typed::UniquePendingId,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use scylla::{
    client::session::Session,
    statement::{
        batch::{Batch, BatchType},
        prepared::PreparedStatement,
        Consistency,
    },
};

use super::{CqlKeyspaceName, PrototypeBindValue};

pub const BRANCH_TO_PENDING_TABLE: &str =
    "d04b6h9_canonical_ref_to_pending";
pub const PENDING_TO_BRANCH_TABLE: &str =
    "d04b6h9_pending_to_canonical_ref";
pub const PENDING_REWARD_PROOF_TABLE: &str =
    "d04b6h9_pending_reward_top_proof";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum BranchExactQueryId {
    CreateBranchToPending = 1,
    CreatePendingToBranch = 2,
    CreatePendingRewardProof = 3,
    PutBranchToPending = 4,
    PutPendingToBranch = 5,
    PutPendingRewardProof = 6,
    ReadBranchToPending = 7,
    ReadPendingToBranch = 8,
    ReadPendingRewardProof = 9,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactQuery {
    id: BranchExactQueryId,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl BranchExactQuery {
    pub const fn id(&self) -> BranchExactQueryId {
        self.id
    }

    pub fn cql(&self) -> &str {
        &self.cql
    }

    pub const fn bind_shape(&self) -> &'static [&'static str] {
        self.bind_shape
    }
}

/// Single source of CQL for the prototype adapter and query-golden tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactQueries {
    queries: [BranchExactQuery; 9],
}

impl BranchExactQueries {
    pub fn new(keyspace: &CqlKeyspaceName) -> Self {
        let forward = format!(
            "{}.{}",
            keyspace.as_str(),
            BRANCH_TO_PENDING_TABLE
        );
        let reverse = format!(
            "{}.{}",
            keyspace.as_str(),
            PENDING_TO_BRANCH_TABLE
        );
        let proof = format!(
            "{}.{}",
            keyspace.as_str(),
            PENDING_REWARD_PROOF_TABLE
        );
        Self {
            queries: [
                query(
                    BranchExactQueryId::CreateBranchToPending,
                    format!(
                        "CREATE TABLE IF NOT EXISTS {forward} (canonical_ref blob, pending_id bigint, PRIMARY KEY ((canonical_ref), pending_id))"
                    ),
                    &[],
                ),
                query(
                    BranchExactQueryId::CreatePendingToBranch,
                    format!(
                        "CREATE TABLE IF NOT EXISTS {reverse} (pending_id bigint, canonical_ref blob, PRIMARY KEY ((pending_id), canonical_ref))"
                    ),
                    &[],
                ),
                query(
                    BranchExactQueryId::CreatePendingRewardProof,
                    format!(
                        "CREATE TABLE IF NOT EXISTS {proof} (pending_id bigint PRIMARY KEY, value blob)"
                    ),
                    &[],
                ),
                query(
                    BranchExactQueryId::PutBranchToPending,
                    format!(
                        "INSERT INTO {forward} (canonical_ref, pending_id) VALUES (?, ?) USING TIMESTAMP ?"
                    ),
                    &["BLOB", "BIGINT", "BIGINT"],
                ),
                query(
                    BranchExactQueryId::PutPendingToBranch,
                    format!(
                        "INSERT INTO {reverse} (pending_id, canonical_ref) VALUES (?, ?) USING TIMESTAMP ?"
                    ),
                    &["BIGINT", "BLOB", "BIGINT"],
                ),
                query(
                    BranchExactQueryId::PutPendingRewardProof,
                    format!(
                        "INSERT INTO {proof} (pending_id, value) VALUES (?, ?) USING TIMESTAMP ?"
                    ),
                    &["BIGINT", "BLOB", "BIGINT"],
                ),
                query(
                    BranchExactQueryId::ReadBranchToPending,
                    format!(
                        "SELECT pending_id FROM {forward} WHERE canonical_ref = ?"
                    ),
                    &["BLOB"],
                ),
                query(
                    BranchExactQueryId::ReadPendingToBranch,
                    format!(
                        "SELECT canonical_ref FROM {reverse} WHERE pending_id = ?"
                    ),
                    &["BIGINT"],
                ),
                query(
                    BranchExactQueryId::ReadPendingRewardProof,
                    format!(
                        "SELECT value FROM {proof} WHERE pending_id = ?"
                    ),
                    &["BIGINT"],
                ),
            ],
        }
    }

    pub fn get(&self, id: BranchExactQueryId) -> &BranchExactQuery {
        &self.queries[id as usize - 1]
    }

    pub fn all(&self) -> impl Iterator<Item = &BranchExactQuery> {
        self.queries.iter()
    }

    pub fn golden(&self) -> String {
        let mut output = String::new();
        for query in self.all() {
            output.push_str(&format!(
                "{:?}\n{}\n{}\n",
                query.id(),
                query.cql(),
                query.bind_shape().join(",")
            ));
        }
        output
    }
}

fn query(
    id: BranchExactQueryId,
    cql: String,
    bind_shape: &'static [&'static str],
) -> BranchExactQuery {
    BranchExactQuery {
        id,
        cql,
        bind_shape,
    }
}

/// Immutable retry unit for the two physical mapping rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchPendingPairPutPlan<Hash> {
    mapping: BranchPendingMapping<Hash>,
    canonical_ref: Vec<u8>,
    pending_id: i64,
    write_timestamp_us: i64,
    digest: BranchPendingMappingDigest,
}

impl<Hash: Q256BitHash> BranchPendingPairPutPlan<Hash> {
    pub fn new(
        mapping: BranchPendingMapping<Hash>,
        timestamp: CommitWriteTimestampUs,
    ) -> Self {
        Self {
            canonical_ref: mapping.canonical_chain_bytes().to_vec(),
            pending_id: mapping.pending_id().get() as i64,
            write_timestamp_us: timestamp.as_i64(),
            digest: mapping.digest(),
            mapping,
        }
    }

    pub const fn mapping(&self) -> &BranchPendingMapping<Hash> {
        &self.mapping
    }

    pub const fn digest(&self) -> BranchPendingMappingDigest {
        self.digest
    }

    pub const fn write_timestamp_us(&self) -> i64 {
        self.write_timestamp_us
    }

    pub fn forward_bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::Blob(self.canonical_ref.clone()),
            PrototypeBindValue::BigInt(self.pending_id),
            PrototypeBindValue::BigInt(self.write_timestamp_us),
        ]
    }

    pub fn reverse_bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::BigInt(self.pending_id),
            PrototypeBindValue::Blob(self.canonical_ref.clone()),
            PrototypeBindValue::BigInt(self.write_timestamp_us),
        ]
    }

    pub fn forward_read_bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![PrototypeBindValue::Blob(self.canonical_ref.clone())]
    }

    pub fn reverse_read_bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![PrototypeBindValue::BigInt(self.pending_id)]
    }

    fn canonical_ref_bytes(&self) -> &[u8] {
        &self.canonical_ref
    }
}

/// Exact proof payload moved out of `checkpointed_object_table`'s mixed axis.
/// It can only be constructed from the actual protocol proof type, never from
/// a digest-only mutation payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingRewardProofPutPlan {
    pending_id: i64,
    stored_value: Vec<u8>,
    canonical_value: Vec<u8>,
    write_timestamp_us: i64,
}

impl PendingRewardProofPutPlan {
    pub fn try_new<Hash: Q256BitHash>(
        pending_id: UniquePendingId,
        proof: &TagTreeMerkleProof<Hash>,
        timestamp: CommitWriteTimestampUs,
    ) -> anyhow::Result<Self> {
        let canonical_value = proof.psy_ser_to_bytes_vec()?;
        let stored_value = crate::compression::compress(&canonical_value)?;
        Ok(Self {
            pending_id: pending_id.get() as i64,
            stored_value,
            canonical_value,
            write_timestamp_us: timestamp.as_i64(),
        })
    }

    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::BigInt(self.pending_id),
            PrototypeBindValue::Blob(self.stored_value.clone()),
            PrototypeBindValue::BigInt(self.write_timestamp_us),
        ]
    }

    pub fn read_bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![PrototypeBindValue::BigInt(self.pending_id)]
    }

    pub fn canonical_value(&self) -> &[u8] {
        &self.canonical_value
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactReadError {
    MissingForward,
    MissingReverse,
    ForwardConflict { rows: Vec<i64> },
    ReverseConflict { rows: usize },
    MalformedCanonicalRef(String),
}

impl fmt::Display for BranchExactReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactReadError {}

/// Require exactly one matching clustering row. Multiple mappings are a hard
/// conflict, not last-write-wins repair.
pub fn verify_forward_rows<Hash: Q256BitHash>(
    plan: &BranchPendingPairPutPlan<Hash>,
    rows: Vec<i64>,
) -> Result<(), BranchExactReadError> {
    match rows.as_slice() {
        [] => Err(BranchExactReadError::MissingForward),
        [pending] if *pending == plan.pending_id => Ok(()),
        _ => Err(BranchExactReadError::ForwardConflict { rows }),
    }
}

pub fn verify_reverse_rows<Hash: Q256BitHash>(
    plan: &BranchPendingPairPutPlan<Hash>,
    rows: Vec<Vec<u8>>,
) -> Result<(), BranchExactReadError> {
    for row in &rows {
        BranchPendingMapping::<Hash>::validate_canonical_chain_bytes(row)
            .map_err(|error| BranchExactReadError::MalformedCanonicalRef(error.to_string()))?;
    }
    match rows.as_slice() {
        [] => Err(BranchExactReadError::MissingReverse),
        [canonical] if canonical.as_slice() == plan.canonical_ref_bytes() => Ok(()),
        _ => Err(BranchExactReadError::ReverseConflict { rows: rows.len() }),
    }
}

struct PreparedBranchExact {
    forward_put: PreparedStatement,
    reverse_put: PreparedStatement,
    proof_put: PreparedStatement,
    forward_read: PreparedStatement,
    reverse_read: PreparedStatement,
    proof_read: PreparedStatement,
}

#[allow(dead_code)]
pub(crate) struct BranchExactSchemaMigrationAdapter {
    queries: BranchExactQueries,
    consistency: Consistency,
    prepared: PreparedBranchExact,
}

#[allow(dead_code)]
impl BranchExactSchemaMigrationAdapter {
    pub(crate) async fn create_schema(
        session: &Session,
        keyspace: CqlKeyspaceName,
    ) -> anyhow::Result<()> {
        let queries = BranchExactQueries::new(&keyspace);
        for id in [
            BranchExactQueryId::CreateBranchToPending,
            BranchExactQueryId::CreatePendingToBranch,
            BranchExactQueryId::CreatePendingRewardProof,
        ] {
            session.query_unpaged(queries.get(id).cql(), &[]).await?;
        }
        Ok(())
    }

    pub(crate) async fn prepare_with_consistency(
        session: &Session,
        keyspace: CqlKeyspaceName,
        consistency: Consistency,
    ) -> anyhow::Result<Self> {
        let queries = BranchExactQueries::new(&keyspace);
        let prepared = PreparedBranchExact {
            forward_put: prepare(
                session,
                queries.get(BranchExactQueryId::PutBranchToPending),
                consistency,
            )
            .await?,
            reverse_put: prepare(
                session,
                queries.get(BranchExactQueryId::PutPendingToBranch),
                consistency,
            )
            .await?,
            proof_put: prepare(
                session,
                queries.get(BranchExactQueryId::PutPendingRewardProof),
                consistency,
            )
            .await?,
            forward_read: prepare(
                session,
                queries.get(BranchExactQueryId::ReadBranchToPending),
                consistency,
            )
            .await?,
            reverse_read: prepare(
                session,
                queries.get(BranchExactQueryId::ReadPendingToBranch),
                consistency,
            )
            .await?,
            proof_read: prepare(
                session,
                queries.get(BranchExactQueryId::ReadPendingRewardProof),
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

    pub(crate) async fn put_pair<Hash: Q256BitHash>(
        &self,
        session: &Session,
        plan: &BranchPendingPairPutPlan<Hash>,
    ) -> anyhow::Result<()> {
        let mut batch = Batch::new(BatchType::Logged);
        batch.set_consistency(self.consistency);
        batch.set_is_idempotent(true);
        batch.append_statement(self.prepared.forward_put.clone());
        batch.append_statement(self.prepared.reverse_put.clone());
        session
            .batch(
                &batch,
                (
                    (
                        plan.canonical_ref.clone(),
                        plan.pending_id,
                        plan.write_timestamp_us,
                    ),
                    (
                        plan.pending_id,
                        plan.canonical_ref.clone(),
                        plan.write_timestamp_us,
                    ),
                ),
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn verify_pair<Hash: Q256BitHash>(
        &self,
        session: &Session,
        plan: &BranchPendingPairPutPlan<Hash>,
    ) -> anyhow::Result<()> {
        let rows = session
            .execute_unpaged(
                &self.prepared.forward_read,
                (plan.canonical_ref_bytes(),),
            )
            .await?
            .into_rows_result()?;
        let mut forward = Vec::new();
        for row in rows.rows::<(i64,)>()? {
            forward.push(row?.0);
        }
        verify_forward_rows(plan, forward)?;

        let rows = session
            .execute_unpaged(&self.prepared.reverse_read, (plan.pending_id,))
            .await?
            .into_rows_result()?;
        let mut reverse = Vec::new();
        for row in rows.rows::<(Vec<u8>,)>()? {
            reverse.push(row?.0);
        }
        verify_reverse_rows(plan, reverse)?;
        Ok(())
    }

    pub(crate) async fn put_pending_reward_proof(
        &self,
        session: &Session,
        plan: &PendingRewardProofPutPlan,
    ) -> anyhow::Result<()> {
        session
            .execute_unpaged(
                &self.prepared.proof_put,
                (
                    plan.pending_id,
                    plan.stored_value.as_slice(),
                    plan.write_timestamp_us,
                ),
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn read_pending_reward_proof<Hash: Q256BitHash>(
        &self,
        session: &Session,
        pending_id: UniquePendingId,
    ) -> anyhow::Result<Option<TagTreeMerkleProof<Hash>>> {
        let row = session
            .execute_unpaged(&self.prepared.proof_read, (pending_id.get() as i64,))
            .await?
            .into_rows_result()?
            .maybe_first_row::<(Vec<u8>,)>()?;
        row.map(|row| {
            TagTreeMerkleProof::<Hash>::psy_ser_from_owned_bytes_vec(
                crate::compression::decompress(&row.0)?,
            )
        })
        .transpose()
    }

    pub(crate) const fn queries(&self) -> &BranchExactQueries {
        &self.queries
    }
}

async fn prepare(
    session: &Session,
    query: &BranchExactQuery,
    consistency: Consistency,
) -> anyhow::Result<PreparedStatement> {
    let mut statement = session.prepare(query.cql()).await?;
    statement.set_consistency(consistency);
    statement.set_is_idempotent(true);
    Ok(statement)
}

#[cfg(test)]
mod tests {
    use parth_core::{
        PHash,
        crypto::hash::tag_tree::TagTreeMerkleProof,
        protocol::core_types::Q256BitHash,
    };
    use psy_data::protocol::canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef, NetworkId,
    };

    use super::*;
    use crate::rollback::PRODUCTION_CQL_CAPABILITIES;

    fn chain(epoch: u64, height: u64, byte: u8) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            NetworkId::try_from_chain_id(0x6979_7350).unwrap(),
            ChainEpoch::new(epoch),
            CheckpointRef::new(
                CheckpointId::new(height),
                CheckpointHash::from_last_chain_hash(PHash::from_owned_32bytes([
                    byte; 32
                ])),
            ),
        )
    }

    fn plan(epoch: u64, pending: u64) -> BranchPendingPairPutPlan<PHash> {
        BranchPendingPairPutPlan::new(
            BranchPendingMapping::new(
                chain(epoch, 100, 7),
                UniquePendingId::try_new(pending).unwrap(),
            ),
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
        )
    }

    #[test]
    fn schema_is_append_only_and_never_height_keyed() {
        let queries = BranchExactQueries::new(&CqlKeyspaceName::try_new("ks").unwrap());
        let forward = queries.get(BranchExactQueryId::CreateBranchToPending).cql();
        let reverse = queries.get(BranchExactQueryId::CreatePendingToBranch).cql();
        assert!(forward.contains("PRIMARY KEY ((canonical_ref), pending_id)"));
        assert!(reverse.contains("PRIMARY KEY ((pending_id), canonical_ref)"));
        assert!(!forward.contains("checkpoint_id"));
        assert!(!reverse.contains("checkpoint_id"));
    }

    #[test]
    fn every_put_requires_an_explicit_timestamp() {
        let queries = BranchExactQueries::new(&CqlKeyspaceName::try_new("ks").unwrap());
        for id in [
            BranchExactQueryId::PutBranchToPending,
            BranchExactQueryId::PutPendingToBranch,
            BranchExactQueryId::PutPendingRewardProof,
        ] {
            assert!(queries.get(id).cql().contains("USING TIMESTAMP ?"));
        }
    }

    #[test]
    fn same_height_and_hash_in_new_epoch_has_a_different_partition() {
        let old = plan(4, 901);
        let reopened = plan(5, 902);
        assert_ne!(
            old.forward_read_bind_values(),
            reopened.forward_read_bind_values()
        );
        assert_ne!(old.digest(), reopened.digest());
    }

    #[test]
    fn mapping_bind_order_and_retry_are_stable() {
        let first = plan(4, 901);
        let retry = first.clone();
        assert_eq!(first.forward_bind_values(), retry.forward_bind_values());
        assert_eq!(first.reverse_bind_values(), retry.reverse_bind_values());
        assert_eq!(first.digest(), retry.digest());
        assert_eq!(
            first.forward_bind_values(),
            vec![
                PrototypeBindValue::Blob(first.mapping().canonical_chain_bytes().to_vec()),
                PrototypeBindValue::BigInt(901),
                PrototypeBindValue::BigInt(1_000),
            ]
        );
    }

    #[test]
    fn conflicting_rows_fail_closed_in_both_directions() {
        let expected = plan(4, 901);
        assert_eq!(verify_forward_rows(&expected, vec![901]), Ok(()));
        assert!(matches!(
            verify_forward_rows(&expected, vec![901, 902]),
            Err(BranchExactReadError::ForwardConflict { .. })
        ));
        assert_eq!(
            verify_reverse_rows(
                &expected,
                vec![expected.mapping().canonical_chain_bytes().to_vec()]
            ),
            Ok(())
        );
        assert!(matches!(
            verify_reverse_rows(
                &expected,
                vec![
                    expected.mapping().canonical_chain_bytes().to_vec(),
                    chain(5, 100, 7).to_canonical_bytes().to_vec(),
                ]
            ),
            Err(BranchExactReadError::ReverseConflict { .. })
        ));
    }

    #[test]
    fn malformed_reverse_identity_is_not_treated_as_absence() {
        let expected = plan(4, 901);
        assert!(matches!(
            verify_reverse_rows(&expected, vec![vec![0; 65]]),
            Err(BranchExactReadError::MalformedCanonicalRef(_))
        ));
        let mut unknown = expected.mapping().canonical_chain_bytes().to_vec();
        unknown[8..10].copy_from_slice(&2_u16.to_le_bytes());
        assert!(matches!(
            verify_reverse_rows(&expected, vec![unknown]),
            Err(BranchExactReadError::MalformedCanonicalRef(_))
        ));
    }

    #[test]
    fn pending_reward_proof_has_a_dedicated_pending_partition() {
        let pending = UniquePendingId::try_new(901).unwrap();
        let proof = TagTreeMerkleProof::<PHash>::new_empty();
        let plan = PendingRewardProofPutPlan::try_new(
            pending,
            &proof,
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
        )
        .unwrap();
        assert!(!plan.canonical_value().is_empty());
        assert_eq!(
            plan.read_bind_values(),
            vec![PrototypeBindValue::BigInt(901)]
        );
        let queries = BranchExactQueries::new(&CqlKeyspaceName::try_new("ks").unwrap());
        assert!(queries
            .get(BranchExactQueryId::CreatePendingRewardProof)
            .cql()
            .contains("pending_id bigint PRIMARY KEY"));
        assert!(!queries
            .get(BranchExactQueryId::CreatePendingRewardProof)
            .cql()
            .contains("obj_id"));
    }

    #[test]
    fn production_capabilities_remain_false() {
        assert!(!PRODUCTION_CQL_CAPABILITIES.explicit_write_timestamp);
        assert!(!PRODUCTION_CQL_CAPABILITIES.delete_adapter);
    }

    #[test]
    fn prototype_is_not_registered_in_production_setup() {
        const SETUP: &str = include_str!("../psy_setup.rs");
        assert!(!SETUP.contains(BRANCH_TO_PENDING_TABLE));
        assert!(!SETUP.contains(PENDING_TO_BRANCH_TABLE));
        assert!(!SETUP.contains(PENDING_REWARD_PROOF_TABLE));
    }

    #[test]
    fn query_golden_is_deterministic_and_complete() {
        let queries = BranchExactQueries::new(&CqlKeyspaceName::try_new("ks").unwrap());
        assert_eq!(queries.all().count(), 9);
        assert_eq!(queries.golden(), queries.golden());
        assert!(queries.golden().contains("PutBranchToPending"));
    }
}
