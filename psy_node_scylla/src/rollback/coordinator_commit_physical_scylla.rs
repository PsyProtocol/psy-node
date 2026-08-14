//! Scylla execution and exact reconciliation for Coordinator typed writes.
//!
//! This executor consumes only a validated Coordinator physical schedule. It
//! dispatches to the existing rollback-aware family adapters plus two narrow
//! Coordinator families (key-only public-key projection and pending-keyed
//! Realm reward materialization). Once the independent narrow writer is
//! durably `WritesVerified`, this executor can bind both exact observations
//! into the complete 23-domain boundary. It still cannot commit the source,
//! persist a manifest, update backups, or publish a canonical head.

use std::collections::BTreeSet;

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    coordinator_commit_source::CoordinatorCommitSource,
    coordinator_normal_commit_coverage::CoordinatorNormalCommitWriteDomain,
    typed::{
        CheckpointId, MutationOperation, MutationValue,
        TypedTableKey,
    },
};
use scylla::{
    client::session::Session,
    statement::{prepared::PreparedStatement, Consistency},
};

use crate::{compression, utils::u64_to_i64_exact};

use super::{
    BranchExactWriterVerified,
    CheckpointKivAdapter, CheckpointKivPutBinding, CheckpointMerkleAdapter,
    CheckpointMerklePutBinding, CheckpointObjectSingleAdapter,
    CheckpointObjectSinglePutBinding, CheckpointRootPairAdapter,
    CheckpointRootPairPutPlan, CqlKeyspaceName, LatestInfoBeforeImage,
    LatestInfoTransitionPlan, MutableSingletonAdapter,
    PublicKeyProjectionAdapter, PublicKeyProjectionPutBinding,
    ScyllaPhysicalTableId, SealedTimestampedPutBatch, TimestampedWriteKind, U64SingletonBeforeImage,
    U64SingletonTransitionPlan, physical_descriptor,
    coordinator_commit_physical_execution::{
        CoordinatorCommitExpectedRow, CoordinatorCommitExpectedValue,
        CoordinatorCommitObservedRow, CoordinatorCommitPhysicalExecutionSchedule,
        CoordinatorCommitPhysicalPreflight, CoordinatorTypedRowsExactObservation,
    },
    coordinator_commit_full_write::CoordinatorCommitFullWriteObservation,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CoordinatorCommitReadFamily {
    CheckpointKiv,
    CheckpointObject,
    CheckpointMerkle,
    CheckpointRootPair,
    MutableSingleton,
    PublicKeyProjection,
    RealmRewardNode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CoordinatorCommitScyllaWriteAction {
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
    PublicKeyProjection {
        index: usize,
        binding: PublicKeyProjectionPutBinding,
    },
    RealmRewardNode { index: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CoordinatorCommitScyllaWritePlan {
    actions: Vec<CoordinatorCommitScyllaWriteAction>,
}

impl CoordinatorCommitScyllaWritePlan {
    fn try_new<Hash: Q256BitHash>(
        schedule: &CoordinatorCommitPhysicalExecutionSchedule<Hash>,
        observed: &[Option<CoordinatorCommitObservedRow>],
        preflight: &CoordinatorCommitPhysicalPreflight,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            observed.len() == schedule.rows().len(),
            "Coordinator write-plan observation count differs from schedule",
        );
        let checkpoint = CheckpointId::try_new(
            schedule.candidate().checkpoint().checkpoint_id().get(),
        )
        .map_err(|_| anyhow::anyhow!("Coordinator candidate checkpoint is outside typed range"))?;
        let mut requested = vec![false; schedule.rows().len()];
        for &index in preflight.write_indices() {
            let selected = requested
                .get_mut(index)
                .ok_or_else(|| anyhow::anyhow!("preflight selected an unknown row"))?;
            anyhow::ensure!(!*selected, "preflight selected one row twice");
            *selected = true;
        }

        let root_indices = root_pair_indices(schedule)?;
        let root_requested = root_indices.iter().any(|&index| requested[index]);
        let root_plan = root_requested
            .then(|| root_pair_plan(schedule, root_indices))
            .transpose()?;

        let mut actions = Vec::new();
        for (index, row) in schedule.rows().iter().enumerate() {
            if root_indices.contains(&index) {
                if root_requested && index == root_indices[0] {
                    actions.push(CoordinatorCommitScyllaWriteAction::CheckpointRootPair {
                        indices: root_indices,
                        plan: root_plan
                            .clone()
                            .expect("requested root pair has a checked plan"),
                    });
                }
                continue;
            }
            if !requested[index] {
                continue;
            }
            let action = match read_family(row.physical_table())? {
                CoordinatorCommitReadFamily::CheckpointKiv => {
                    CheckpointKivPutBinding::try_from_sealed(row.sealed())?;
                    CoordinatorCommitScyllaWriteAction::CheckpointKiv { index }
                }
                CoordinatorCommitReadFamily::CheckpointObject => {
                    CheckpointObjectSinglePutBinding::try_from_sealed(row.sealed())?;
                    CoordinatorCommitScyllaWriteAction::CheckpointObject { index }
                }
                CoordinatorCommitReadFamily::CheckpointMerkle => {
                    CheckpointMerklePutBinding::try_from_sealed(row.sealed())?;
                    CoordinatorCommitScyllaWriteAction::CheckpointMerkle { index }
                }
                CoordinatorCommitReadFamily::MutableSingleton => match row.domain() {
                    CoordinatorNormalCommitWriteDomain::LatestCheckpoint => {
                        let before = observed[index]
                            .as_ref()
                            .map(observed_value)
                            .transpose()?
                            .map(decode_u64)
                            .transpose()?
                            .map_or(
                                U64SingletonBeforeImage::Absent,
                                U64SingletonBeforeImage::Present,
                            );
                        let plan = match schedule.write_kind() {
                            TimestampedWriteKind::AuthorityCommit => {
                                U64SingletonTransitionPlan::try_for_commit(
                                    row.sealed(),
                                    checkpoint,
                                    before,
                                )?
                            }
                            TimestampedWriteKind::NewBranchAfterFence => {
                                U64SingletonTransitionPlan::try_for_new_branch_commit(
                                    row.sealed(),
                                    checkpoint,
                                    before,
                                )?
                            }
                        };
                        CoordinatorCommitScyllaWriteAction::LatestCheckpoint { index, plan }
                    }
                    CoordinatorNormalCommitWriteDomain::LatestL2BlockState => {
                        let before = observed[index]
                            .as_ref()
                            .map(observed_value)
                            .transpose()?
                            .map(|value| LatestInfoBeforeImage::Present(value.to_vec()))
                            .unwrap_or(LatestInfoBeforeImage::Absent);
                        let plan = match schedule.write_kind() {
                            TimestampedWriteKind::AuthorityCommit => {
                                LatestInfoTransitionPlan::try_for_commit(
                                    row.sealed(),
                                    checkpoint,
                                    before,
                                )?
                            }
                            TimestampedWriteKind::NewBranchAfterFence => {
                                LatestInfoTransitionPlan::try_for_new_branch_commit(
                                    row.sealed(),
                                    checkpoint,
                                    before,
                                )?
                            }
                        };
                        CoordinatorCommitScyllaWriteAction::LatestInfo { index, plan }
                    }
                    domain => anyhow::bail!(
                        "Coordinator mutable singleton is not admitted for {domain:?}"
                    ),
                },
                CoordinatorCommitReadFamily::PublicKeyProjection => {
                    CoordinatorCommitScyllaWriteAction::PublicKeyProjection {
                        index,
                        binding: PublicKeyProjectionPutBinding::try_from_sealed(
                            row.sealed(),
                            checkpoint,
                        )?,
                    }
                }
                CoordinatorCommitReadFamily::RealmRewardNode => {
                    CoordinatorRealmRewardNodeBinding::try_from_expected(row)?;
                    CoordinatorCommitScyllaWriteAction::RealmRewardNode { index }
                }
                CoordinatorCommitReadFamily::CheckpointRootPair => {
                    unreachable!("root-pair rows are grouped before dispatch")
                }
            };
            actions.push(action);
        }
        Ok(Self { actions })
    }
}

/// Prepared family dispatcher for all 19 typed Coordinator semantic domains.
pub(crate) struct CoordinatorCommitPhysicalScyllaExecutor {
    checkpoint_kiv: CheckpointKivAdapter,
    checkpoint_object: CheckpointObjectSingleAdapter,
    checkpoint_merkle: CheckpointMerkleAdapter,
    checkpoint_root_pair: CheckpointRootPairAdapter,
    mutable_singleton: MutableSingletonAdapter,
    public_key_projection: PublicKeyProjectionAdapter,
    realm_reward_node: CoordinatorRealmRewardNodeAdapter,
}

impl CoordinatorCommitPhysicalScyllaExecutor {
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
            public_key_projection: PublicKeyProjectionAdapter::prepare_with_consistency(
                session,
                keyspace.clone(),
                consistency,
            )
            .await?,
            realm_reward_node: CoordinatorRealmRewardNodeAdapter::prepare_with_consistency(
                session,
                keyspace,
                consistency,
            )
            .await?,
        })
    }

    pub(crate) async fn read_all<Hash: Q256BitHash>(
        &self,
        session: &Session,
        schedule: &CoordinatorCommitPhysicalExecutionSchedule<Hash>,
    ) -> anyhow::Result<Vec<Option<CoordinatorCommitObservedRow>>> {
        let checkpoint = CheckpointId::try_new(
            schedule.candidate().checkpoint().checkpoint_id().get(),
        )
        .map_err(|_| anyhow::anyhow!("Coordinator candidate checkpoint is outside typed range"))?;
        let mut observed = Vec::with_capacity(schedule.rows().len());
        for row in schedule.rows() {
            observed.push(self.read_one(session, row, checkpoint).await?);
        }
        Ok(observed)
    }

    /// Execute one retry-safe typed-row attempt. Value rows may reconcile an
    /// uncertain driver result by exact value+writetime readback. Key-only
    /// projection rows require a successful INSERT acknowledgement in this
    /// attempt in addition to exact presence.
    pub(crate) async fn write_and_verify<Hash: Q256BitHash>(
        &self,
        session: &Session,
        schedule: &CoordinatorCommitPhysicalExecutionSchedule<Hash>,
    ) -> anyhow::Result<CoordinatorTypedRowsExactObservation<Hash>> {
        let before = self.read_all(session, schedule).await?;
        let preflight = schedule.preflight(&before)?;
        let plan = CoordinatorCommitScyllaWritePlan::try_new(
            schedule,
            &before,
            &preflight,
        )?;
        let mut acknowledged = BTreeSet::new();
        let mut write_error = None;
        for action in &plan.actions {
            match self.execute_action(session, schedule, action).await {
                Ok(()) => {
                    if let CoordinatorCommitScyllaWriteAction::PublicKeyProjection {
                        index,
                        ..
                    } = action
                    {
                        acknowledged.insert(*index);
                    }
                }
                Err(error) => {
                    write_error = Some(error);
                    break;
                }
            }
        }
        let after = self.read_all(session, schedule).await.map_err(|read_error| {
            match &write_error {
                Some(write_error) => anyhow::anyhow!(
                    "Coordinator typed write returned {write_error:#}; reconciliation read failed: {read_error:#}"
                ),
                None => read_error,
            }
        })?;
        match schedule.verify_after_write(&after, &acknowledged) {
            Ok(observation) => Ok(observation),
            Err(verification) => match write_error {
                Some(write_error) => Err(anyhow::anyhow!(
                    "Coordinator typed write returned {write_error:#}; exact reconciliation failed: {verification}"
                )),
                None => Err(verification.into()),
            },
        }
    }

    /// Execute/reconcile all typed rows and join them to the already durable
    /// six-row narrow observation. The resulting value proves the complete
    /// physical write surface, but grants no committed-source or head-publish
    /// authority.
    pub(crate) async fn write_and_verify_full<Hash: Q256BitHash>(
        &self,
        session: &Session,
        source: &CoordinatorCommitSource<Hash>,
        schedule: &CoordinatorCommitPhysicalExecutionSchedule<Hash>,
        narrow: &BranchExactWriterVerified<Hash>,
    ) -> anyhow::Result<CoordinatorCommitFullWriteObservation<Hash>> {
        let typed = self.write_and_verify(session, schedule).await?;
        CoordinatorCommitFullWriteObservation::try_from_storage(
            source,
            schedule,
            narrow,
            typed,
        )
        .map_err(Into::into)
    }

    async fn execute_action<Hash: Q256BitHash>(
        &self,
        session: &Session,
        schedule: &CoordinatorCommitPhysicalExecutionSchedule<Hash>,
        action: &CoordinatorCommitScyllaWriteAction,
    ) -> anyhow::Result<()> {
        match action {
            CoordinatorCommitScyllaWriteAction::CheckpointKiv { index } => {
                self.checkpoint_kiv
                    .put(session, schedule.rows()[*index].sealed())
                    .await
            }
            CoordinatorCommitScyllaWriteAction::CheckpointObject { index } => {
                self.checkpoint_object
                    .put(session, schedule.rows()[*index].sealed())
                    .await
            }
            CoordinatorCommitScyllaWriteAction::CheckpointMerkle { index } => {
                self.checkpoint_merkle
                    .put(session, schedule.rows()[*index].sealed())
                    .await
            }
            CoordinatorCommitScyllaWriteAction::CheckpointRootPair {
                indices,
                plan,
            } => {
                anyhow::ensure!(
                    indices.iter().all(|&index| index < schedule.rows().len()),
                    "root pair action references an unknown row",
                );
                self.checkpoint_root_pair.put_pair(session, plan).await
            }
            CoordinatorCommitScyllaWriteAction::LatestInfo { index, plan } => {
                anyhow::ensure!(
                    schedule.rows()[*index].physical_table()
                        == ScyllaPhysicalTableId::LatestInfo,
                    "latest-info action differs from schedule",
                );
                self.mutable_singleton.put_latest_info(session, plan).await
            }
            CoordinatorCommitScyllaWriteAction::LatestCheckpoint { index, plan } => {
                anyhow::ensure!(
                    schedule.rows()[*index].physical_table()
                        == ScyllaPhysicalTableId::U64Singleton,
                    "latest-checkpoint action differs from schedule",
                );
                self.mutable_singleton
                    .put_latest_checkpoint(session, plan)
                    .await
            }
            CoordinatorCommitScyllaWriteAction::PublicKeyProjection {
                binding,
                ..
            } => self.public_key_projection.put_one(session, binding).await,
            CoordinatorCommitScyllaWriteAction::RealmRewardNode { index } => {
                self.realm_reward_node
                    .put(session, &schedule.rows()[*index])
                    .await
            }
        }
    }

    async fn read_one(
        &self,
        session: &Session,
        row: &CoordinatorCommitExpectedRow,
        checkpoint: CheckpointId,
    ) -> anyhow::Result<Option<CoordinatorCommitObservedRow>> {
        if row.requires_write_acknowledgement() {
            let binding = PublicKeyProjectionPutBinding::try_from_sealed(
                row.sealed(),
                checkpoint,
            )?;
            return Ok(self
                .public_key_projection
                .read_exact(session, &binding)
                .await?
                .then(|| {
                    CoordinatorCommitObservedRow::key_only(
                        row.physical_table(),
                        row.locator().to_vec(),
                    )
                }));
        }

        let actual = match read_family(row.physical_table())? {
            CoordinatorCommitReadFamily::CheckpointKiv => {
                self.checkpoint_kiv.read_exact(session, row.sealed()).await?
            }
            CoordinatorCommitReadFamily::CheckpointObject => {
                self.checkpoint_object.read_exact(session, row.sealed()).await?
            }
            CoordinatorCommitReadFamily::CheckpointMerkle => {
                self.checkpoint_merkle.read_exact(session, row.sealed()).await?
            }
            CoordinatorCommitReadFamily::CheckpointRootPair => {
                self.checkpoint_root_pair.read_exact(session, row.sealed()).await?
            }
            CoordinatorCommitReadFamily::MutableSingleton => {
                self.mutable_singleton.read_exact(session, row.sealed()).await?
            }
            CoordinatorCommitReadFamily::RealmRewardNode => {
                self.realm_reward_node.read_exact(session, row).await?
            }
            CoordinatorCommitReadFamily::PublicKeyProjection => {
                anyhow::bail!("public-key projection lost key-only schedule marker")
            }
        };
        Ok(actual.map(|(value, writetime_us)| {
            CoordinatorCommitObservedRow::value(
                row.physical_table(),
                row.locator().to_vec(),
                value,
                writetime_us,
            )
        }))
    }
}

fn read_family(table: ScyllaPhysicalTableId) -> anyhow::Result<CoordinatorCommitReadFamily> {
    use CoordinatorCommitReadFamily as F;
    use ScyllaPhysicalTableId as P;
    Ok(match table {
        P::CheckpointLeaf
        | P::L2BlockState
        | P::CheckpointStateRoots
        | P::CheckpointZkProofAndTransition => F::CheckpointKiv,
        P::UserPublicKey
        | P::ContractStateTreeHeight
        | P::ContractLeaf
        | P::ContractCodeDefinition => F::CheckpointObject,
        P::GlobalUserTree
        | P::GlobalCheckpointTree
        | P::UserRegistrationTree
        | P::GlobalContractTree
        | P::ContractFunctionTree => F::CheckpointMerkle,
        P::CheckpointRootToCheckpointIdK1
        | P::CheckpointRootToCheckpointIdK2 => F::CheckpointRootPair,
        P::LatestInfo | P::U64Singleton => F::MutableSingleton,
        P::PublicKeyHashToUserIds => F::PublicKeyProjection,
        P::RealmRewardsTreeNodeKey => F::RealmRewardNode,
        unsupported => anyhow::bail!(
            "Coordinator typed executor does not admit table {unsupported:?}"
        ),
    })
}

fn observed_value(observed: &CoordinatorCommitObservedRow) -> anyhow::Result<&[u8]> {
    match observed {
        CoordinatorCommitObservedRow::Value { value, .. } => Ok(value),
        CoordinatorCommitObservedRow::KeyOnlyPresent { .. } => {
            anyhow::bail!("mutable singleton observed a key-only row")
        }
    }
}

fn decode_u64(bytes: &[u8]) -> anyhow::Result<u64> {
    Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| {
        anyhow::anyhow!("CQL u64 readback must contain exactly eight bytes")
    })?))
}

fn root_pair_indices<Hash: Q256BitHash>(
    schedule: &CoordinatorCommitPhysicalExecutionSchedule<Hash>,
) -> anyhow::Result<[usize; 2]> {
    let k1 = schedule
        .rows()
        .iter()
        .position(|row| {
            row.physical_table() == ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1
        })
        .ok_or_else(|| anyhow::anyhow!("Coordinator schedule has no root k1 row"))?;
    let k2 = schedule
        .rows()
        .iter()
        .position(|row| {
            row.physical_table() == ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2
        })
        .ok_or_else(|| anyhow::anyhow!("Coordinator schedule has no root k2 row"))?;
    Ok([k1, k2])
}

fn root_pair_plan<Hash: Q256BitHash>(
    schedule: &CoordinatorCommitPhysicalExecutionSchedule<Hash>,
    indices: [usize; 2],
) -> anyhow::Result<CheckpointRootPairPutPlan> {
    let members = [
        schedule.rows()[indices[0]].sealed().clone(),
        schedule.rows()[indices[1]].sealed().clone(),
    ];
    let batch = SealedTimestampedPutBatch::try_from_exact_members(members.to_vec())?;
    CheckpointRootPairPutPlan::try_from_sealed(&batch).map_err(Into::into)
}

/// Test-only production binding audit. It proves every selected physical row
/// can be encoded by the exact adapter used by the executable dispatcher.
#[cfg(test)]
pub(super) fn validate_schedule_bindings<Hash: Q256BitHash>(
    schedule: &CoordinatorCommitPhysicalExecutionSchedule<Hash>,
) -> anyhow::Result<usize> {
    let observed = vec![None; schedule.rows().len()];
    let preflight = schedule.preflight(&observed)?;
    let plan = CoordinatorCommitScyllaWritePlan::try_new(
        schedule,
        &observed,
        &preflight,
    )?;
    anyhow::ensure!(
        plan.actions.len() <= schedule.rows().len(),
        "grouped physical action count exceeds scheduled rows",
    );
    Ok(schedule.rows().len())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CoordinatorRealmRewardNodeQueries {
    put: String,
    exact_read: String,
}

impl CoordinatorRealmRewardNodeQueries {
    fn new(keyspace: &CqlKeyspaceName) -> Self {
        let table = physical_descriptor(ScyllaPhysicalTableId::RealmRewardsTreeNodeKey)
            .physical_name;
        let qualified = format!("{}.{table}", keyspace.as_str());
        Self {
            put: format!(
                "INSERT INTO {qualified} (obj_id, checkpoint_id, value) VALUES (?, ?, ?) USING TIMESTAMP ?"
            ),
            exact_read: format!(
                "SELECT value, writetime(value) FROM {qualified} WHERE obj_id = ? AND checkpoint_id = ?"
            ),
        }
    }
}

struct CoordinatorRealmRewardNodeBinding {
    realm: i64,
    pending: i64,
    stored_value: Vec<u8>,
    write_timestamp_us: i64,
}

impl CoordinatorRealmRewardNodeBinding {
    fn try_from_expected(row: &CoordinatorCommitExpectedRow) -> anyhow::Result<Self> {
        anyhow::ensure!(
            row.domain() == CoordinatorNormalCommitWriteDomain::RealmRewardNode,
            "reward adapter requires the Coordinator reward domain",
        );
        let mutation = row.sealed().resolved().mutation();
        anyhow::ensure!(
            mutation.physical_table() == ScyllaPhysicalTableId::RealmRewardsTreeNodeKey,
            "reward adapter requires the reward materialization table",
        );
        let (realm, pending) = match mutation.key() {
            TypedTableKey::RealmRewardNode { realm, pending } => {
                (u64_to_i64_exact(realm.get()), u64_to_i64_exact(pending.get()))
            }
            _ => anyhow::bail!("reward adapter received another typed key"),
        };
        let canonical_value = match mutation.operation() {
            MutationOperation::Put(MutationValue::PsyCanonicalBytes(value)) => value.clone(),
            _ => anyhow::bail!("reward adapter requires canonical bytes"),
        };
        anyhow::ensure!(
            row.expected() == &CoordinatorCommitExpectedValue::Value(canonical_value.clone()),
            "reward expected value differs from sealed mutation",
        );
        Ok(Self {
            realm,
            pending,
            stored_value: compression::compress(&canonical_value)?,
            write_timestamp_us: row.timestamp().as_i64(),
        })
    }
}

struct CoordinatorRealmRewardNodeAdapter {
    put: PreparedStatement,
    exact_read: PreparedStatement,
}

impl CoordinatorRealmRewardNodeAdapter {
    async fn prepare_with_consistency(
        session: &Session,
        keyspace: CqlKeyspaceName,
        consistency: Consistency,
    ) -> anyhow::Result<Self> {
        let queries = CoordinatorRealmRewardNodeQueries::new(&keyspace);
        Ok(Self {
            put: prepare_idempotent(session, &queries.put, consistency).await?,
            exact_read: prepare_idempotent(session, &queries.exact_read, consistency).await?,
        })
    }

    async fn put(
        &self,
        session: &Session,
        row: &CoordinatorCommitExpectedRow,
    ) -> anyhow::Result<()> {
        let binding = CoordinatorRealmRewardNodeBinding::try_from_expected(row)?;
        session
            .execute_unpaged(
                &self.put,
                (
                    binding.realm,
                    binding.pending,
                    binding.stored_value,
                    binding.write_timestamp_us,
                ),
            )
            .await?;
        Ok(())
    }

    async fn read_exact(
        &self,
        session: &Session,
        row: &CoordinatorCommitExpectedRow,
    ) -> anyhow::Result<Option<(Vec<u8>, i64)>> {
        let binding = CoordinatorRealmRewardNodeBinding::try_from_expected(row)?;
        let Some((stored, writetime)) = session
            .execute_unpaged(&self.exact_read, (binding.realm, binding.pending))
            .await?
            .into_rows_result()?
            .maybe_first_row::<(Option<Vec<u8>>, Option<i64>)>()?
        else {
            return Ok(None);
        };
        let stored = stored.ok_or_else(|| anyhow::anyhow!("reward value is null"))?;
        let writetime = writetime.ok_or_else(|| anyhow::anyhow!("reward writetime is null"))?;
        Ok(Some((compression::decompress(&stored)?, writetime)))
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
    use psy_node_core::store::coordinator_normal_commit_coverage::{
        CoordinatorNormalCommitWriteDomain as D,
    };

    use super::*;

    #[test]
    fn every_typed_coordinator_domain_has_a_family() {
        let domains = [
            (D::CheckpointZkProof, ScyllaPhysicalTableId::CheckpointZkProofAndTransition),
            (D::ContractLeaf, ScyllaPhysicalTableId::ContractLeaf),
            (D::ContractCodeDefinition, ScyllaPhysicalTableId::ContractCodeDefinition),
            (D::ContractStateTreeHeight, ScyllaPhysicalTableId::ContractStateTreeHeight),
            (D::ContractFunctionMerkle, ScyllaPhysicalTableId::ContractFunctionTree),
            (D::GlobalContractMerkle, ScyllaPhysicalTableId::GlobalContractTree),
            (D::UserPublicKey, ScyllaPhysicalTableId::UserPublicKey),
            (D::PublicKeyToUser, ScyllaPhysicalTableId::PublicKeyHashToUserIds),
            (D::UserRegistrationMerkle, ScyllaPhysicalTableId::UserRegistrationTree),
            (D::GlobalUserMerkle, ScyllaPhysicalTableId::GlobalUserTree),
            (D::RealmRewardNode, ScyllaPhysicalTableId::RealmRewardsTreeNodeKey),
            (D::CheckpointStateRoots, ScyllaPhysicalTableId::CheckpointStateRoots),
            (D::L2BlockState, ScyllaPhysicalTableId::L2BlockState),
            (D::LatestL2BlockState, ScyllaPhysicalTableId::LatestInfo),
            (D::CheckpointLeaf, ScyllaPhysicalTableId::CheckpointLeaf),
            (D::GlobalCheckpointMerkle, ScyllaPhysicalTableId::GlobalCheckpointTree),
            (D::CheckpointRootByHash, ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1),
            (D::CheckpointRootByCheckpoint, ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2),
            (D::LatestCheckpoint, ScyllaPhysicalTableId::U64Singleton),
        ];
        for (_, table) in domains {
            read_family(table).unwrap();
        }
        assert_eq!(domains.len(), 19);
    }

    #[test]
    fn reward_queries_are_full_pk_and_explicit_timestamp() {
        let queries = CoordinatorRealmRewardNodeQueries::new(
            &CqlKeyspaceName::try_new("rollback_test").unwrap(),
        );
        assert!(queries.put.contains("USING TIMESTAMP ?"));
        assert!(queries.exact_read.contains("writetime(value)"));
        assert!(queries.exact_read.contains("obj_id = ? AND checkpoint_id = ?"));
    }
}
