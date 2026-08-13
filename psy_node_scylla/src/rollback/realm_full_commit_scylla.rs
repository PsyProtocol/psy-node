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
            CheckpointId, CheckpointedObjectKey,
            LogicalMutation, MutationOperation, MutationValue, TypedTableKey,
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
    CheckpointRootPairPutPlan, CqlKeyspaceName, ImtCursorPutBinding,
    ImtFamilyAdapter, ImtIndexPutBinding, ImtLeafPutBinding,
    LatestInfoBeforeImage, LatestInfoTransitionPlan, MutableSingletonAdapter,
    ScyllaPhysicalTableId, TimestampedWriteKind, U64SingletonBeforeImage,
    U64SingletonTransitionPlan, physical_descriptor, seal_commit_put_batch,
    realm_full_commit_execution::{
        RealmFullCommitExecutionSchedule, RealmFullCommitExpectedRow,
        RealmFullCommitObservedRow, RealmFullCommitPreflight,
        RealmTypedRowsExactObservation,
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

    pub(crate) async fn read_exact_physical(
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
        Ok(Some((
            stored.ok_or_else(|| anyhow::anyhow!("global-user proof value is null"))?,
            writetime.ok_or_else(|| anyhow::anyhow!("global-user proof writetime is null"))?,
        )))
    }
}

/// Prepared dispatcher for every physical family admitted by the non-h22
/// full-commit schedule. Exact reads and writes share the same prepared
/// adapters so a driver response can always be reconciled against the
/// physical value and writetime selected by the sealed schedule.
pub(crate) struct RealmFullCommitScyllaExecutor {
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

#[derive(Clone, Debug, Eq, PartialEq)]
enum RealmFullCommitScyllaWriteAction {
    CheckpointKiv { index: usize },
    CheckpointObject { index: usize },
    CheckpointMerkle { index: usize },
    CheckpointRootPair {
        indices: [usize; 2],
        plan: CheckpointRootPairPutPlan,
    },
    LatestInfo {
        index: usize,
        plan: LatestInfoTransitionPlan,
    },
    LatestCheckpoint {
        index: usize,
        plan: U64SingletonTransitionPlan,
    },
    ImtLeaf { index: usize },
    ImtIndex { index: usize },
    ImtCursor { index: usize },
    GlobalUserProofException { index: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RealmFullCommitScyllaWritePlan {
    actions: Vec<RealmFullCommitScyllaWriteAction>,
}

impl RealmFullCommitScyllaWritePlan {
    fn try_new(
        schedule: &RealmFullCommitExecutionSchedule,
        observed: &[Option<RealmFullCommitObservedRow>],
        preflight: &RealmFullCommitPreflight,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            observed.len() == schedule.rows().len(),
            "full-commit write plan observation count differs from schedule",
        );
        let checkpoint = schedule_checkpoint(schedule)?;
        let mut requested = vec![false; schedule.rows().len()];
        for &index in preflight.write_indices() {
            let selected = requested
                .get_mut(index)
                .ok_or_else(|| anyhow::anyhow!("preflight selected an unknown row index"))?;
            anyhow::ensure!(!*selected, "preflight selected a row twice");
            *selected = true;
        }

        let root_pair_indices = root_pair_indices(schedule)?;
        let root_pair_requested = root_pair_indices
            .iter()
            .any(|&index| requested[index]);
        let root_pair_plan = root_pair_requested
            .then(|| root_pair_plan(schedule, root_pair_indices))
            .transpose()?;

        let mut actions = Vec::new();
        for (index, row) in schedule.rows().iter().enumerate() {
            if root_pair_indices.contains(&index) {
                if root_pair_requested && index == root_pair_indices[0] {
                    actions.push(RealmFullCommitScyllaWriteAction::CheckpointRootPair {
                        indices: root_pair_indices,
                        plan: root_pair_plan
                            .clone()
                            .expect("requested root pair has a validated plan"),
                    });
                }
                continue;
            }
            if !requested[index] {
                continue;
            }
            let action = match read_family(row.physical_table())? {
                RealmFullCommitReadFamily::CheckpointKiv => {
                    CheckpointKivPutBinding::try_from_sealed(row.sealed())?;
                    RealmFullCommitScyllaWriteAction::CheckpointKiv { index }
                }
                RealmFullCommitReadFamily::CheckpointObject => {
                    CheckpointObjectSinglePutBinding::try_from_sealed(row.sealed())?;
                    RealmFullCommitScyllaWriteAction::CheckpointObject { index }
                }
                RealmFullCommitReadFamily::CheckpointMerkle => {
                    CheckpointMerklePutBinding::try_from_sealed(row.sealed())?;
                    RealmFullCommitScyllaWriteAction::CheckpointMerkle { index }
                }
                RealmFullCommitReadFamily::MutableSingleton => {
                    match row.domain() {
                        RealmNormalCommitWriteDomain::LatestCheckpoint => {
                            let before = observed[index]
                                .as_ref()
                                .map(|row| decode_u64_readback(row.value()))
                                .transpose()?
                                .map_or(
                                    U64SingletonBeforeImage::Absent,
                                    U64SingletonBeforeImage::Present,
                                );
                            RealmFullCommitScyllaWriteAction::LatestCheckpoint {
                                index,
                                plan: U64SingletonTransitionPlan::try_for_commit(
                                    row.sealed(),
                                    checkpoint,
                                    before,
                                )?,
                            }
                        }
                        RealmNormalCommitWriteDomain::LatestL2BlockState
                        | RealmNormalCommitWriteDomain::RealmAuthorityObservation => {
                            let before = observed[index]
                                .as_ref()
                                .map(|row| {
                                    LatestInfoBeforeImage::Present(row.value().to_vec())
                                })
                                .unwrap_or(LatestInfoBeforeImage::Absent);
                            RealmFullCommitScyllaWriteAction::LatestInfo {
                                index,
                                plan: LatestInfoTransitionPlan::try_for_commit(
                                    row.sealed(),
                                    checkpoint,
                                    before,
                                )?,
                            }
                        }
                        domain => anyhow::bail!(
                            "mutable singleton table is not admitted for domain {domain:?}"
                        ),
                    }
                }
                RealmFullCommitReadFamily::ImtLeaf => {
                    ImtLeafPutBinding::try_from_sealed(row.sealed())?;
                    RealmFullCommitScyllaWriteAction::ImtLeaf { index }
                }
                RealmFullCommitReadFamily::ImtIndex => {
                    ImtIndexPutBinding::try_from_sealed(row.sealed())?;
                    RealmFullCommitScyllaWriteAction::ImtIndex { index }
                }
                RealmFullCommitReadFamily::ImtCursor => {
                    ImtCursorPutBinding::try_from_sealed(row.sealed())?;
                    RealmFullCommitScyllaWriteAction::ImtCursor { index }
                }
                RealmFullCommitReadFamily::GlobalUserProofException => {
                    RealmGlobalUserProofBinding::try_from_expected(row)?;
                    RealmFullCommitScyllaWriteAction::GlobalUserProofException { index }
                }
                RealmFullCommitReadFamily::CheckpointRootPair => {
                    unreachable!("root-pair rows are grouped before per-row dispatch")
                }
            };
            actions.push(action);
        }
        Ok(Self { actions })
    }
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

fn schedule_checkpoint(
    schedule: &RealmFullCommitExecutionSchedule,
) -> anyhow::Result<CheckpointId> {
    let row = schedule
        .rows()
        .iter()
        .find(|row| row.domain() == RealmNormalCommitWriteDomain::LatestCheckpoint)
        .ok_or_else(|| anyhow::anyhow!("full-commit schedule has no latest checkpoint row"))?;
    CheckpointId::try_new(decode_u64_readback(row.expected_value())?)
        .map_err(|_| anyhow::anyhow!("scheduled latest checkpoint is outside the typed range"))
}

fn decode_u64_readback(bytes: &[u8]) -> anyhow::Result<u64> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("CQL u64 readback must contain exactly 8 bytes"))?;
    Ok(u64::from_be_bytes(bytes))
}

fn root_pair_indices(
    schedule: &RealmFullCommitExecutionSchedule,
) -> anyhow::Result<[usize; 2]> {
    let by_hash = schedule
        .rows()
        .iter()
        .position(|row| {
            row.domain() == RealmNormalCommitWriteDomain::CheckpointRootByHash
        })
        .ok_or_else(|| anyhow::anyhow!("full-commit schedule has no root-to-checkpoint row"))?;
    let by_checkpoint = schedule
        .rows()
        .iter()
        .position(|row| {
            row.domain() == RealmNormalCommitWriteDomain::CheckpointRootByCheckpoint
        })
        .ok_or_else(|| anyhow::anyhow!("full-commit schedule has no checkpoint-to-root row"))?;
    anyhow::ensure!(by_hash != by_checkpoint, "root-pair schedule rows overlap");
    Ok([by_hash, by_checkpoint])
}

fn root_pair_plan(
    schedule: &RealmFullCommitExecutionSchedule,
    indices: [usize; 2],
) -> anyhow::Result<CheckpointRootPairPutPlan> {
    let by_hash = &schedule.rows()[indices[0]];
    let by_checkpoint = &schedule.rows()[indices[1]];
    let root = match by_hash.sealed().resolved().mutation().key() {
        TypedTableKey::CheckpointRootByHash(root) => root.clone(),
        _ => anyhow::bail!("root-pair by-hash row has the wrong typed key"),
    };
    let checkpoint = match by_checkpoint.sealed().resolved().mutation().key() {
        TypedTableKey::CheckpointRootByCheckpoint(checkpoint) => *checkpoint,
        _ => anyhow::bail!("root-pair by-checkpoint row has the wrong typed key"),
    };
    anyhow::ensure!(
        by_hash.timestamp() == by_checkpoint.timestamp(),
        "root-pair schedule uses mixed timestamps",
    );
    let sealed = seal_commit_put_batch(
        LogicalMutation::CheckpointRootMapping { root, checkpoint },
        by_hash.timestamp(),
    )?;
    for row in [by_hash, by_checkpoint] {
        let candidate = sealed
            .members()
            .iter()
            .find(|member| {
                member.resolved().mutation().physical_table() == row.physical_table()
            })
            .ok_or_else(|| anyhow::anyhow!("resealed root pair lost a physical direction"))?;
        anyhow::ensure!(
            candidate == row.sealed(),
            "root-pair schedule differs from the canonical logical reseal",
        );
    }
    CheckpointRootPairPutPlan::try_from_sealed(&sealed).map_err(anyhow::Error::from)
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

#[cfg(test)]
pub(super) fn validate_schedule_write_plan(
    schedule: &RealmFullCommitExecutionSchedule,
    observed: &[Option<RealmFullCommitObservedRow>],
) -> anyhow::Result<usize> {
    let preflight = schedule.preflight(observed)?;
    Ok(RealmFullCommitScyllaWritePlan::try_new(schedule, observed, &preflight)?
        .actions
        .len())
}

impl RealmFullCommitScyllaExecutor {
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

    /// Exact point-read for one immutable rollback-inventory PUT. The
    /// inventory supplies the typed key, logical value, and sealed timestamp;
    /// this method returns only after the production family adapter observes
    /// that exact triple in the hot table.
    pub(crate) async fn read_inventory_put_exact(
        &self,
        session: &Session,
        put: &super::SealedTimestampedPut,
    ) -> anyhow::Result<RealmFullCommitObservedRow> {
        let expected = RealmFullCommitExpectedRow::try_from_inventory(put)?;
        let actual = self
            .read_one(session, &expected)
            .await?
            .ok_or_else(|| anyhow::anyhow!("rollback inventory hot row is missing"))?;
        let observed = RealmFullCommitObservedRow::new(
            expected.physical_table(),
            expected.locator().to_vec(),
            actual.0,
            actual.1,
        );
        expected.require_exact_observation(&observed)?;
        Ok(observed)
    }

    pub(crate) async fn read_inventory_put_physical_exact(
        &self,
        session: &Session,
        put: &super::SealedTimestampedPut,
    ) -> anyhow::Result<RealmFullCommitObservedRow> {
        let expected = RealmFullCommitExpectedRow::try_from_inventory(put)?;
        let logical = self
            .read_one(session, &expected)
            .await?
            .ok_or_else(|| anyhow::anyhow!("rollback inventory hot row is missing"))?;
        let physical = self
            .read_one_physical(session, &expected)
            .await?
            .ok_or_else(|| anyhow::anyhow!("rollback inventory physical hot row is missing"))?;
        anyhow::ensure!(logical.1 == physical.1, "logical/physical reads changed writetime");
        let observed = RealmFullCommitObservedRow::new_physical(
            expected.physical_table(),
            expected.locator().to_vec(),
            logical.0,
            physical.0,
            logical.1,
        );
        expected.require_exact_observation(&observed)?;
        Ok(observed)
    }

    /// Execute one retry-safe non-h22 write attempt and prove its result by
    /// re-reading every scheduled row. A driver error never decides the
    /// outcome: if all exact values and writetimes are present, the attempt is
    /// successful; otherwise the returned error requires a fresh retry or
    /// reports the conflicting physical state.
    pub(crate) async fn write_and_verify(
        &self,
        session: &Session,
        schedule: &RealmFullCommitExecutionSchedule,
    ) -> anyhow::Result<RealmTypedRowsExactObservation> {
        let before = self.read_all(session, schedule).await?;
        let preflight = schedule.preflight(&before)?;
        let plan = RealmFullCommitScyllaWritePlan::try_new(
            schedule,
            &before,
            &preflight,
        )?;
        let write_error = self.execute_plan(session, schedule, &plan).await.err();
        let after = self.read_all(session, schedule).await.map_err(|error| {
            if let Some(write_error) = &write_error {
                anyhow::anyhow!(
                    "full-commit write returned {write_error:#}; exact reconciliation read also failed: {error:#}"
                )
            } else {
                error
            }
        })?;
        match schedule.verify_after_write(&after) {
            Ok(observation) => Ok(observation),
            Err(verification) => {
                if let Some(write_error) = write_error {
                    Err(anyhow::anyhow!(
                        "full-commit write returned {write_error:#}; exact reconciliation failed: {verification}"
                    ))
                } else {
                    Err(verification.into())
                }
            }
        }
    }

    async fn execute_plan(
        &self,
        session: &Session,
        schedule: &RealmFullCommitExecutionSchedule,
        plan: &RealmFullCommitScyllaWritePlan,
    ) -> anyhow::Result<()> {
        for action in &plan.actions {
            self.execute_action(session, schedule, action).await?;
        }
        Ok(())
    }

    async fn execute_action(
        &self,
        session: &Session,
        schedule: &RealmFullCommitExecutionSchedule,
        action: &RealmFullCommitScyllaWriteAction,
    ) -> anyhow::Result<()> {
        match action {
                RealmFullCommitScyllaWriteAction::CheckpointKiv { index } => {
                    self.checkpoint_kiv
                        .put(session, schedule.rows()[*index].sealed())
                        .await?;
                }
                RealmFullCommitScyllaWriteAction::CheckpointObject { index } => {
                    self.checkpoint_object
                        .put(session, schedule.rows()[*index].sealed())
                        .await?;
                }
                RealmFullCommitScyllaWriteAction::CheckpointMerkle { index } => {
                    self.checkpoint_merkle
                        .put(session, schedule.rows()[*index].sealed())
                        .await?;
                }
                RealmFullCommitScyllaWriteAction::CheckpointRootPair {
                    indices,
                    plan,
                } => {
                    anyhow::ensure!(
                        indices.iter().all(|&index| index < schedule.rows().len()),
                        "root-pair write action references an unknown schedule row",
                    );
                    self.checkpoint_root_pair.put_pair(session, plan).await?;
                }
                RealmFullCommitScyllaWriteAction::LatestInfo { index, plan } => {
                    anyhow::ensure!(
                        schedule.rows()[*index].physical_table()
                            == ScyllaPhysicalTableId::LatestInfo,
                        "latest-info action does not match its schedule row",
                    );
                    self.mutable_singleton
                        .put_latest_info(session, plan)
                        .await?;
                }
                RealmFullCommitScyllaWriteAction::LatestCheckpoint {
                    index,
                    plan,
                } => {
                    anyhow::ensure!(
                        schedule.rows()[*index].physical_table()
                            == ScyllaPhysicalTableId::U64Singleton,
                        "latest-checkpoint action does not match its schedule row",
                    );
                    self.mutable_singleton
                        .put_latest_checkpoint(session, plan)
                        .await?;
                }
                RealmFullCommitScyllaWriteAction::ImtLeaf { index } => {
                    let binding = ImtLeafPutBinding::try_from_sealed(
                        schedule.rows()[*index].sealed(),
                    )?;
                    self.imt.put_leaf(session, &binding).await?;
                }
                RealmFullCommitScyllaWriteAction::ImtIndex { index } => {
                    let binding = ImtIndexPutBinding::try_from_sealed(
                        schedule.rows()[*index].sealed(),
                    )?;
                    self.imt.put_index(session, &binding).await?;
                }
                RealmFullCommitScyllaWriteAction::ImtCursor { index } => {
                    let binding = ImtCursorPutBinding::try_from_sealed(
                        schedule.rows()[*index].sealed(),
                    )?;
                    self.imt.put_cursor(session, &binding).await?;
                }
                RealmFullCommitScyllaWriteAction::GlobalUserProofException {
                    index,
                } => {
                    self.global_user_proof
                        .put(session, &schedule.rows()[*index])
                        .await?;
                }
        }
        Ok(())
    }

    /// Qualification-only crash-window hook. It executes a bounded prefix of
    /// the same private write plan and returns without reconciliation so the
    /// RF=3 harness can rebuild the executor and prove fresh retry convergence.
    #[cfg(test)]
    pub(super) async fn qualification_write_prefix(
        &self,
        session: &Session,
        schedule: &RealmFullCommitExecutionSchedule,
        limit: usize,
    ) -> anyhow::Result<usize> {
        let before = self.read_all(session, schedule).await?;
        let preflight = schedule.preflight(&before)?;
        let plan = RealmFullCommitScyllaWritePlan::try_new(
            schedule,
            &before,
            &preflight,
        )?;
        let count = limit.min(plan.actions.len());
        for action in plan.actions.iter().take(count) {
            self.execute_action(session, schedule, action).await?;
        }
        Ok(count)
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


    async fn read_one_physical(
        &self,
        session: &Session,
        row: &RealmFullCommitExpectedRow,
    ) -> anyhow::Result<Option<(Vec<u8>, i64)>> {
        use RealmFullCommitReadFamily as F;
        match read_family(row.physical_table())? {
            F::CheckpointKiv => self.checkpoint_kiv.read_exact_physical(session, row.sealed()).await,
            F::CheckpointObject => self.checkpoint_object.read_exact_physical(session, row.sealed()).await,
            F::CheckpointRootPair => self.checkpoint_root_pair.read_exact_physical(session, row.sealed()).await,
            F::MutableSingleton => self.mutable_singleton.read_exact_physical(session, row.sealed()).await,
            F::GlobalUserProofException => self.global_user_proof.read_exact_physical(session, row).await,
            F::CheckpointMerkle | F::ImtLeaf | F::ImtIndex | F::ImtCursor => {
                self.read_one(session, row).await
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
