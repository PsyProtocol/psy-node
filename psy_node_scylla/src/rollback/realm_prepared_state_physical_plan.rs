//! Storage-private physical expansion of the five prepared Realm state rows.
//!
//! The driver-independent mutation graph proves the cross-table Merkle graph
//! and binds one exact prepared payload. This module resolves those checked
//! rows through the rollback registry, applies the h22 commit timestamp, and
//! reuses the coordinated IMT leaf/index/cursor planner. It does not execute
//! CQL and does not expose a writer or authority receipt.

use std::{error::Error, fmt};

use parth_core::{felt::QFelt64, protocol::core_types::Q256BitHash};
use psy_data::prepared_block::realm::PsyPreparedRealmBlockStateUpdates;
use psy_node_core::store::{
    branch_exact_schema::AuthorityScope,
    realm_imt_mutation_graph::{
        RealmImtMutationGraphDigest, RealmImtMutationGraphError,
        SealedRealmImtMutationGraph,
    },
    realm_normal_commit_coverage::{
        RealmNormalCommitCoveragePlan, RealmNormalCommitWriteDomain,
    },
    realm_prepared_payload::RealmPreparedPayloadCommitment,
    timestamp::CommitWriteTimestampUs,
};

use super::{
    ImtCheckpointWritePlan, ImtCursorSnapshot, ImtLeafPutBinding,
    ImtPlanError, SealedTimestampedPut, TimestampedMutationError,
    realm_full_commit_plan::RealmCommitPhysicalDomainBatch, seal_commit_put,
};

/// Exact state-domain batches derived from one sealed mutation graph and one
/// exact prepared payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RealmPreparedStatePhysicalBatches {
    authority: AuthorityScope,
    coverage_plan: RealmNormalCommitCoveragePlan,
    prepared_payload_commitment: RealmPreparedPayloadCommitment,
    mutation_graph_digest: RealmImtMutationGraphDigest,
    timestamp: CommitWriteTimestampUs,
    batches: Vec<RealmCommitPhysicalDomainBatch>,
}

impl RealmPreparedStatePhysicalBatches {
    pub(crate) fn try_new<F, Hash, Hasher>(
        prepared: &PsyPreparedRealmBlockStateUpdates<Hash>,
        graph: &SealedRealmImtMutationGraph<Hash, Hasher>,
        timestamp: CommitWriteTimestampUs,
        cursor_before: &[ImtCursorSnapshot],
    ) -> Result<Self, RealmPreparedStatePhysicalPlanError>
    where
        F: QFelt64,
        Hash: Q256BitHash,
    {
        let coverage_plan = RealmNormalCommitCoveragePlan::from_prepared(prepared);
        if !coverage_plan.invokes_state_update_branch() {
            return Err(RealmPreparedStatePhysicalPlanError::StateBranchRequired);
        }

        let rows = graph.expand_exact_prepared_rows::<F>(prepared)?;
        let mut batches = vec![
            seal_batch(
                RealmNormalCommitWriteDomain::UserLeaf,
                rows.user_leaves(),
                timestamp,
            )?,
            seal_batch(
                RealmNormalCommitWriteDomain::ContractStateMerkle,
                rows.contract_state_merkle(),
                timestamp,
            )?,
            seal_batch(
                RealmNormalCommitWriteDomain::UserContractMerkle,
                rows.user_contract_merkle(),
                timestamp,
            )?,
            seal_batch(
                RealmNormalCommitWriteDomain::GlobalUserMerkle,
                rows.global_user_merkle(),
                timestamp,
            )?,
        ];

        if coverage_plan.invokes_imt_branch() {
            let sealed_leaves = rows
                .imt_leaves()
                .iter()
                .cloned()
                .map(|mutation| seal_commit_put(mutation, timestamp))
                .collect::<Result<Vec<_>, _>>()?;
            let imt = ImtCheckpointWritePlan::try_from_sealed_leaves(
                &sealed_leaves,
                cursor_before,
            )?;
            let leaf_puts = select_first_physical_leaves(&sealed_leaves, &imt)?;
            let index_puts = imt
                .index_puts()
                .iter()
                .map(|binding| seal_commit_put(binding.durable_supplement(), timestamp))
                .collect::<Result<Vec<_>, _>>()?;
            let cursor_puts = imt
                .cursor_puts()
                .iter()
                .map(|binding| seal_commit_put(binding.durable_supplement(), timestamp))
                .collect::<Result<Vec<_>, _>>()?;
            batches.push(RealmCommitPhysicalDomainBatch::new(
                RealmNormalCommitWriteDomain::ImtLeaf,
                leaf_puts,
            ));
            batches.push(RealmCommitPhysicalDomainBatch::new(
                RealmNormalCommitWriteDomain::ImtKeyIndex,
                index_puts,
            ));
            batches.push(RealmCommitPhysicalDomainBatch::new(
                RealmNormalCommitWriteDomain::ImtCursor,
                cursor_puts,
            ));
        } else if !rows.imt_leaves().is_empty() || !cursor_before.is_empty() {
            return Err(RealmPreparedStatePhysicalPlanError::UnexpectedImtInputs);
        }

        Ok(Self {
            authority: graph.authority(),
            coverage_plan,
            prepared_payload_commitment: rows.prepared_payload_commitment(),
            mutation_graph_digest: graph.digest(),
            timestamp,
            batches,
        })
    }

    pub(crate) const fn coverage_plan(&self) -> RealmNormalCommitCoveragePlan {
        self.coverage_plan
    }

    pub(crate) const fn authority(&self) -> AuthorityScope { self.authority }

    pub(crate) const fn prepared_payload_commitment(
        &self,
    ) -> RealmPreparedPayloadCommitment {
        self.prepared_payload_commitment
    }

    pub(crate) const fn mutation_graph_digest(&self) -> RealmImtMutationGraphDigest {
        self.mutation_graph_digest
    }

    pub(crate) const fn timestamp(&self) -> CommitWriteTimestampUs {
        self.timestamp
    }

    pub(crate) fn batches(&self) -> &[RealmCommitPhysicalDomainBatch] {
        &self.batches
    }

    pub(crate) fn into_batches(self) -> Vec<RealmCommitPhysicalDomainBatch> {
        self.batches
    }
}

fn seal_batch(
    domain: RealmNormalCommitWriteDomain,
    mutations: &[psy_node_core::store::typed::LogicalMutation],
    timestamp: CommitWriteTimestampUs,
) -> Result<RealmCommitPhysicalDomainBatch, RealmPreparedStatePhysicalPlanError> {
    if mutations.is_empty() {
        return Err(RealmPreparedStatePhysicalPlanError::EmptyStateDomain {
            domain,
        });
    }
    let puts = mutations
        .iter()
        .cloned()
        .map(|mutation| seal_commit_put(mutation, timestamp))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RealmCommitPhysicalDomainBatch::new(domain, puts))
}

fn select_first_physical_leaves(
    sealed: &[SealedTimestampedPut],
    plan: &ImtCheckpointWritePlan,
) -> Result<Vec<SealedTimestampedPut>, RealmPreparedStatePhysicalPlanError> {
    let mut selected = Vec::with_capacity(plan.leaf_puts().len());
    for expected in plan.leaf_puts() {
        let member = sealed
            .iter()
            .find(|member| {
                ImtLeafPutBinding::try_from_sealed(member)
                    .is_ok_and(|binding| &binding == expected)
            })
            .ok_or(RealmPreparedStatePhysicalPlanError::MissingPlannedImtLeaf)?;
        selected.push(member.clone());
    }
    Ok(selected)
}

#[derive(Debug)]
pub(crate) enum RealmPreparedStatePhysicalPlanError {
    StateBranchRequired,
    EmptyStateDomain { domain: RealmNormalCommitWriteDomain },
    UnexpectedImtInputs,
    MissingPlannedImtLeaf,
    Graph(RealmImtMutationGraphError),
    Timestamped(TimestampedMutationError),
    Imt(ImtPlanError),
}

impl From<RealmImtMutationGraphError> for RealmPreparedStatePhysicalPlanError {
    fn from(value: RealmImtMutationGraphError) -> Self { Self::Graph(value) }
}

impl From<TimestampedMutationError> for RealmPreparedStatePhysicalPlanError {
    fn from(value: TimestampedMutationError) -> Self { Self::Timestamped(value) }
}

impl From<ImtPlanError> for RealmPreparedStatePhysicalPlanError {
    fn from(value: ImtPlanError) -> Self { Self::Imt(value) }
}

impl fmt::Display for RealmPreparedStatePhysicalPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Realm prepared state physical plan: {self:?}")
    }
}

impl Error for RealmPreparedStatePhysicalPlanError {}
