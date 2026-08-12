//! Scylla exact-row reader for the non-h22 portion of one Realm full commit.
//!
//! The reader consumes only rows retained by `RealmFullCommitExecutionSchedule`
//! and dispatches them to existing family adapters. The mixed-axis checkpoint
//! global-user proof remains a narrow, storage-private exception whose binding
//! can only be derived from such a validated schedule row.

use psy_node_core::{
    psy_core_db::core_implementation::constants::CHECKPOINTED_OBJECT_TABLE_OBJ_ID_REALM_ROOT_TO_GLOBAL_USER_TREE_ROOT_MERKLE_PROOF,
    store::{
        realm_normal_commit_coverage::RealmNormalCommitWriteDomain,
        typed::{
            CheckpointedObjectKey, MutationOperation, MutationValue,
            TypedTableKey,
        },
    },
};
use scylla::{
    client::session::Session,
    statement::{prepared::PreparedStatement, Consistency},
};

use crate::{
    compression,
    utils::{convert_checkpoint_id_to_i64, u64_to_i64_exact},
};

use super::{
    CheckpointKivAdapter, CheckpointKivPutBinding, CheckpointMerkleAdapter,
    CheckpointMerklePutBinding, CheckpointObjectSingleAdapter,
    CheckpointObjectSinglePutBinding, CheckpointRootPairAdapter,
    CqlKeyspaceName, ImtCursorPutBinding, ImtFamilyAdapter,
    ImtIndexPutBinding, ImtLeafPutBinding, MutableSingletonAdapter,
    ScyllaPhysicalTableId, TimestampedWriteKind, physical_descriptor,
    realm_full_commit_execution::{
        RealmFullCommitExecutionSchedule, RealmFullCommitExpectedRow,
        RealmFullCommitObservedRow,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum RealmGlobalUserProofQueryKind {
    Put = 1,
    ExactRead = 2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RealmGlobalUserProofQuery {
    kind: RealmGlobalUserProofQueryKind,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl RealmGlobalUserProofQuery {
    pub(crate) const fn kind(&self) -> RealmGlobalUserProofQueryKind {
        self.kind
    }

    pub(crate) fn cql(&self) -> &str { &self.cql }

    pub(crate) const fn bind_shape(&self) -> &'static [&'static str] {
        self.bind_shape
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RealmGlobalUserProofQueries {
    put: RealmGlobalUserProofQuery,
    exact_read: RealmGlobalUserProofQuery,
}

impl RealmGlobalUserProofQueries {
    pub(crate) fn new(keyspace: &CqlKeyspaceName) -> Self {
        let table = physical_descriptor(ScyllaPhysicalTableId::CheckpointedObject)
            .physical_name;
        let qualified = format!("{}.{table}", keyspace.as_str());
        Self {
            put: RealmGlobalUserProofQuery {
                kind: RealmGlobalUserProofQueryKind::Put,
                cql: format!(
                    "INSERT INTO {qualified} (obj_id, checkpoint_id, value) VALUES (?, ?, ?) USING TIMESTAMP ?"
                ),
                bind_shape: &[
                    "obj_id:BIGINT",
                    "checkpoint_id:BIGINT",
                    "value:BLOB",
                    "write_timestamp_us:BIGINT",
                ],
            },
            exact_read: RealmGlobalUserProofQuery {
                kind: RealmGlobalUserProofQueryKind::ExactRead,
                cql: format!(
                    "SELECT value, writetime(value) FROM {qualified} WHERE obj_id = ? AND checkpoint_id = ?"
                ),
                bind_shape: &["obj_id:BIGINT", "checkpoint_id:BIGINT"],
            },
        }
    }

    pub(crate) const fn put(&self) -> &RealmGlobalUserProofQuery {
        &self.put
    }

    pub(crate) const fn exact_read(&self) -> &RealmGlobalUserProofQuery {
        &self.exact_read
    }

    pub(crate) fn render_golden(&self) -> String {
        [self.put(), self.exact_read()]
            .into_iter()
            .map(|query| {
                format!(
                    "{:?}\n{}\n{}\n",
                    query.kind(),
                    query.cql(),
                    query.bind_shape().join(",")
                )
            })
            .collect()
    }
}

struct RealmGlobalUserProofBinding {
    checkpoint_id: i64,
    stored_value: Vec<u8>,
    write_timestamp_us: i64,
}

impl RealmGlobalUserProofBinding {
    fn try_from_expected(row: &RealmFullCommitExpectedRow) -> anyhow::Result<Self> {
        anyhow::ensure!(
            row.domain()
                == RealmNormalCommitWriteDomain::GlobalUserTopProofAtCheckpoint,
            "global-user proof adapter requires the cutover exception domain",
        );
        let sealed = row.sealed();
        let mutation = sealed.resolved().mutation();
        anyhow::ensure!(
            mutation.physical_table() == ScyllaPhysicalTableId::CheckpointedObject,
            "global-user proof adapter requires checkpointed_object_table",
        );
        anyhow::ensure!(
            sealed.write_kind() == TimestampedWriteKind::AuthorityCommit
                && sealed.timestamp() == row.timestamp(),
            "global-user proof seal differs from scheduled authority commit",
        );
        let checkpoint = match mutation.key() {
            TypedTableKey::CheckpointedObject(
                CheckpointedObjectKey::GlobalUserProofAtCheckpoint(checkpoint),
            ) => *checkpoint,
            _ => anyhow::bail!("global-user proof adapter received another key domain"),
        };
        let value = match mutation.operation() {
            MutationOperation::Put(MutationValue::PsyCanonicalBytes(value)) => value,
            _ => anyhow::bail!("global-user proof adapter requires canonical bytes"),
        };
        anyhow::ensure!(
            value.as_slice() == row.expected_value(),
            "global-user proof scheduled value differs from sealed mutation",
        );
        Ok(Self {
            checkpoint_id: convert_checkpoint_id_to_i64(checkpoint.get()),
            stored_value: compression::compress(value)?,
            write_timestamp_us: sealed.timestamp().as_i64(),
        })
    }
}

struct PreparedRealmGlobalUserProof {
    put: PreparedStatement,
    exact_read: PreparedStatement,
}

pub(crate) struct RealmGlobalUserProofExceptionAdapter {
    queries: RealmGlobalUserProofQueries,
    prepared: PreparedRealmGlobalUserProof,
}

impl RealmGlobalUserProofExceptionAdapter {
    pub(crate) async fn prepare_with_consistency(
        session: &Session,
        keyspace: CqlKeyspaceName,
        consistency: Consistency,
    ) -> anyhow::Result<Self> {
        let queries = RealmGlobalUserProofQueries::new(&keyspace);
        Ok(Self {
            prepared: PreparedRealmGlobalUserProof {
                put: prepare_idempotent(session, queries.put().cql(), consistency)
                    .await?,
                exact_read: prepare_idempotent(
                    session,
                    queries.exact_read().cql(),
                    consistency,
                )
                .await?,
            },
            queries,
        })
    }

    pub(crate) const fn queries(&self) -> &RealmGlobalUserProofQueries {
        &self.queries
    }

    pub(crate) async fn put(
        &self,
        session: &Session,
        row: &RealmFullCommitExpectedRow,
    ) -> anyhow::Result<()> {
        let binding = RealmGlobalUserProofBinding::try_from_expected(row)?;
        session
            .execute_unpaged(
                &self.prepared.put,
                (
                    u64_to_i64_exact(
                        CHECKPOINTED_OBJECT_TABLE_OBJ_ID_REALM_ROOT_TO_GLOBAL_USER_TREE_ROOT_MERKLE_PROOF,
                    ),
                    binding.checkpoint_id,
                    binding.stored_value,
                    binding.write_timestamp_us,
                ),
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn read_exact(
        &self,
        session: &Session,
        row: &RealmFullCommitExpectedRow,
    ) -> anyhow::Result<Option<(Vec<u8>, i64)>> {
        let binding = RealmGlobalUserProofBinding::try_from_expected(row)?;
        let Some((stored, writetime)) = session
            .execute_unpaged(
                &self.prepared.exact_read,
                (
                    u64_to_i64_exact(
                        CHECKPOINTED_OBJECT_TABLE_OBJ_ID_REALM_ROOT_TO_GLOBAL_USER_TREE_ROOT_MERKLE_PROOF,
                    ),
                    binding.checkpoint_id,
                ),
            )
            .await?
            .into_rows_result()?
            .maybe_first_row::<(Option<Vec<u8>>, Option<i64>)>()?
        else {
            return Ok(None);
        };
        let stored = stored
            .ok_or_else(|| anyhow::anyhow!("global-user proof value is null"))?;
        let writetime = writetime
            .ok_or_else(|| anyhow::anyhow!("global-user proof writetime is null"))?;
        Ok(Some((compression::decompress(&stored)?, writetime)))
    }
}

/// Prepared dispatcher for every physical family admitted by the non-h22
/// full-commit schedule. It currently performs exact reads only; mutation
/// execution is added after pair/singleton ordering is composed explicitly.
pub(crate) struct RealmFullCommitScyllaExactReader {
    checkpoint_kiv: CheckpointKivAdapter,
    checkpoint_object: CheckpointObjectSingleAdapter,
    checkpoint_merkle: CheckpointMerkleAdapter,
    checkpoint_root_pair: CheckpointRootPairAdapter,
    mutable_singleton: MutableSingletonAdapter,
    imt: ImtFamilyAdapter,
    global_user_proof: RealmGlobalUserProofExceptionAdapter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RealmFullCommitReadFamily {
    CheckpointKiv,
    CheckpointObject,
    CheckpointMerkle,
    CheckpointRootPair,
    MutableSingleton,
    ImtLeaf,
    ImtIndex,
    ImtCursor,
    GlobalUserProofException,
}

fn read_family(
    table: ScyllaPhysicalTableId,
) -> anyhow::Result<RealmFullCommitReadFamily> {
    use RealmFullCommitReadFamily as F;
    use ScyllaPhysicalTableId as P;
    Ok(match table {
        P::CheckpointLeaf
        | P::L2BlockState
        | P::CheckpointStateRoots
        | P::CheckpointZkProofAndTransition => F::CheckpointKiv,
        P::UserLeaf
        | P::UserPublicKey
        | P::ContractStateTreeHeight
        | P::ContractLeaf
        | P::ContractCodeDefinition => F::CheckpointObject,
        P::GlobalUserTree
        | P::UserContractTree
        | P::ContractStateTree
        | P::GlobalCheckpointTree
        | P::UserRegistrationTree
        | P::GlobalContractTree
        | P::ContractFunctionTree => F::CheckpointMerkle,
        P::CheckpointRootToCheckpointIdK1
        | P::CheckpointRootToCheckpointIdK2 => F::CheckpointRootPair,
        P::LatestInfo | P::U64Singleton => F::MutableSingleton,
        P::ImtLeaf => F::ImtLeaf,
        P::ImtKeyIndex => F::ImtIndex,
        P::ImtNextAppendIndex => F::ImtCursor,
        P::CheckpointedObject => F::GlobalUserProofException,
        unsupported => anyhow::bail!(
            "full-commit exact reader does not admit physical table {unsupported:?}"
        ),
    })
}

/// Test-only production binding audit for a complete schedule. This catches a
/// plan fixture that has the right registry identity but cannot be encoded by
/// its real family adapter (for example a non-32-byte Merkle value).
#[cfg(test)]
pub(super) fn validate_schedule_bindings(
    schedule: &RealmFullCommitExecutionSchedule,
) -> anyhow::Result<usize> {
    use RealmFullCommitReadFamily as F;
    for row in schedule.rows() {
        match read_family(row.physical_table())? {
            F::CheckpointKiv => {
                CheckpointKivPutBinding::try_from_sealed(row.sealed())?;
            }
            F::CheckpointObject => {
                CheckpointObjectSinglePutBinding::try_from_sealed(row.sealed())?;
            }
            F::CheckpointMerkle => {
                CheckpointMerklePutBinding::try_from_sealed(row.sealed())?;
            }
            F::ImtLeaf => {
                ImtLeafPutBinding::try_from_sealed(row.sealed())?;
            }
            F::ImtIndex => {
                ImtIndexPutBinding::try_from_sealed(row.sealed())?;
            }
            F::ImtCursor => {
                ImtCursorPutBinding::try_from_sealed(row.sealed())?;
            }
            F::GlobalUserProofException => {
                RealmGlobalUserProofBinding::try_from_expected(row)?;
            }
            F::CheckpointRootPair | F::MutableSingleton => {}
        }
    }
    Ok(schedule.rows().len())
}

impl RealmFullCommitScyllaExactReader {
    pub(crate) async fn prepare_with_consistency(
        session: &Session,
        keyspace: CqlKeyspaceName,
        consistency: Consistency,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            checkpoint_kiv: CheckpointKivAdapter::prepare_with_consistency(
                session,
                keyspace.clone(),
                consistency,
            )
            .await?,
            checkpoint_object: CheckpointObjectSingleAdapter::prepare_with_consistency(
                session,
                keyspace.clone(),
                consistency,
            )
            .await?,
            checkpoint_merkle: CheckpointMerkleAdapter::prepare_with_consistency(
                session,
                keyspace.clone(),
                consistency,
            )
            .await?,
            checkpoint_root_pair: CheckpointRootPairAdapter::prepare_with_consistency(
                session,
                keyspace.clone(),
                consistency,
            )
            .await?,
            mutable_singleton: MutableSingletonAdapter::prepare_with_consistency(
                session,
                keyspace.clone(),
                consistency,
            )
            .await?,
            imt: ImtFamilyAdapter::prepare_with_consistency(
                session,
                keyspace.clone(),
                consistency,
            )
            .await?,
            global_user_proof:
                RealmGlobalUserProofExceptionAdapter::prepare_with_consistency(
                    session,
                    keyspace,
                    consistency,
                )
                .await?,
        })
    }

    pub(crate) async fn read_all(
        &self,
        session: &Session,
        schedule: &RealmFullCommitExecutionSchedule,
    ) -> anyhow::Result<Vec<Option<RealmFullCommitObservedRow>>> {
        let mut observed = Vec::with_capacity(schedule.rows().len());
        for row in schedule.rows() {
            let actual = self.read_one(session, row).await?;
            observed.push(actual.map(|(value, writetime)| {
                RealmFullCommitObservedRow::new(
                    row.physical_table(),
                    row.locator().to_vec(),
                    value,
                    writetime,
                )
            }));
        }
        Ok(observed)
    }

    async fn read_one(
        &self,
        session: &Session,
        row: &RealmFullCommitExpectedRow,
    ) -> anyhow::Result<Option<(Vec<u8>, i64)>> {
        use RealmFullCommitReadFamily as F;
        match read_family(row.physical_table())? {
            F::CheckpointKiv => {
                self.checkpoint_kiv.read_exact(session, row.sealed()).await
            }
            F::CheckpointObject => {
                self.checkpoint_object.read_exact(session, row.sealed()).await
            }
            F::CheckpointMerkle => {
                self.checkpoint_merkle.read_exact(session, row.sealed()).await
            }
            F::CheckpointRootPair => {
                self.checkpoint_root_pair.read_exact(session, row.sealed()).await
            }
            F::MutableSingleton => {
                self.mutable_singleton.read_exact(session, row.sealed()).await
            }
            F::ImtLeaf => {
                let binding = ImtLeafPutBinding::try_from_sealed(row.sealed())?;
                self.imt
                    .read_leaf_exact_with_writetime(session, &binding)
                    .await
            }
            F::ImtIndex => {
                let binding = ImtIndexPutBinding::try_from_sealed(row.sealed())?;
                self.imt
                    .read_index_exact_with_writetime(session, &binding)
                    .await
            }
            F::ImtCursor => {
                let binding = ImtCursorPutBinding::try_from_sealed(row.sealed())?;
                self.imt
                    .read_cursor_exact_with_writetime(session, &binding)
                    .await
            }
            F::GlobalUserProofException => {
                self.global_user_proof.read_exact(session, row).await
            }
        }
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

#[cfg(test)]
mod tests {
    use psy_node_core::store::{
        realm_normal_commit_coverage::{
            H22_BRANCH_EXACT_REALM_DOMAIN_SCOPE, RealmNormalCommitWriteDomain,
        },
    };

    use super::{
        RealmGlobalUserProofQueries, RealmGlobalUserProofQueryKind, read_family,
    };
    use crate::rollback::{CqlKeyspaceName, expected_physical_table};

    #[test]
    fn global_user_proof_exception_queries_are_full_pk_and_timestamped() {
        let queries = RealmGlobalUserProofQueries::new(
            &CqlKeyspaceName::try_new("rollback_test").unwrap(),
        );
        assert_eq!(queries.put().kind(), RealmGlobalUserProofQueryKind::Put);
        assert!(queries.put().cql().contains("USING TIMESTAMP ?"));
        assert_eq!(
            queries.put().bind_shape(),
            [
                "obj_id:BIGINT",
                "checkpoint_id:BIGINT",
                "value:BLOB",
                "write_timestamp_us:BIGINT",
            ]
        );
        assert_eq!(
            queries.exact_read().kind(),
            RealmGlobalUserProofQueryKind::ExactRead,
        );
        assert!(queries.exact_read().cql().contains("writetime(value)"));
        assert!(queries
            .exact_read()
            .cql()
            .contains("WHERE obj_id = ? AND checkpoint_id = ?"));
        assert_eq!(
            queries.render_golden(),
            "Put\nINSERT INTO rollback_test.checkpointed_object_table (obj_id, checkpoint_id, value) VALUES (?, ?, ?) USING TIMESTAMP ?\nobj_id:BIGINT,checkpoint_id:BIGINT,value:BLOB,write_timestamp_us:BIGINT\nExactRead\nSELECT value, writetime(value) FROM rollback_test.checkpointed_object_table WHERE obj_id = ? AND checkpoint_id = ?\nobj_id:BIGINT,checkpoint_id:BIGINT\n"
        );
    }

    #[test]
    fn every_non_h22_full_commit_domain_has_an_exact_read_family() {
        let mut domains = 0;
        for domain in RealmNormalCommitWriteDomain::ALL {
            if H22_BRANCH_EXACT_REALM_DOMAIN_SCOPE.contains(&domain) {
                continue;
            }
            read_family(expected_physical_table(domain)).unwrap();
            domains += 1;
        }
        assert_eq!(domains, 17);
    }
}
