//! Checked, driver-independent input for one complete Realm commit.
//!
//! The real Processor constructs logical mutations while the Scylla adapter
//! owns registry resolution, the durable commit timestamp and execution.  This
//! boundary proves that the Processor supplied every non-h22 semantic domain
//! selected by the real commit path and, when state changes, that the rows came
//! from one exact sealed mutation graph.  It is data, not storage authority.

use std::{collections::BTreeSet, error::Error, fmt};

use parth_core::{felt::QFelt64, protocol::core_types::Q256BitHash};
use psy_data::prepared_block::realm::PsyPreparedRealmBlockStateUpdates;

use super::{
    branch_exact_schema::AuthorityScope,
    realm_imt_mutation_graph::{
        RealmImtMutationGraphDigest, RealmImtMutationGraphError,
        RealmPreparedStateRows, SealedRealmImtMutationGraph,
    },
    realm_normal_commit_coverage::{
        H22_BRANCH_EXACT_REALM_DOMAIN_SCOPE, RealmNormalCommitCoveragePlan,
        RealmNormalCommitWriteDomain,
    },
    realm_prepared_payload::RealmPreparedPayloadCommitment,
    typed::{LogicalMutation, TreeId, TreeSubId, TypedTableKey},
};

const STATE_DOMAINS: [RealmNormalCommitWriteDomain; 7] = [
    RealmNormalCommitWriteDomain::UserLeaf,
    RealmNormalCommitWriteDomain::ContractStateMerkle,
    RealmNormalCommitWriteDomain::ImtLeaf,
    RealmNormalCommitWriteDomain::ImtKeyIndex,
    RealmNormalCommitWriteDomain::ImtCursor,
    RealmNormalCommitWriteDomain::UserContractMerkle,
    RealmNormalCommitWriteDomain::GlobalUserMerkle,
];

/// Logical mutations for exactly one semantic domain outside h22/state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmCommitLogicalDomainBatch {
    domain: RealmNormalCommitWriteDomain,
    mutations: Vec<LogicalMutation>,
}

impl RealmCommitLogicalDomainBatch {
    pub fn new(
        domain: RealmNormalCommitWriteDomain,
        mutations: Vec<LogicalMutation>,
    ) -> Self {
        Self { domain, mutations }
    }

    pub const fn domain(&self) -> RealmNormalCommitWriteDomain {
        self.domain
    }

    pub fn mutations(&self) -> &[LogicalMutation] {
        &self.mutations
    }
}

/// Exact before image for one IMT cursor selected by the Processor store.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RealmImtCursorBeforeImage {
    tree: TreeId,
    tree_sub: TreeSubId,
    next_append_index: u64,
}

impl RealmImtCursorBeforeImage {
    pub const fn new(
        tree: TreeId,
        tree_sub: TreeSubId,
        next_append_index: u64,
    ) -> Self {
        Self {
            tree,
            tree_sub,
            next_append_index,
        }
    }

    pub const fn tree(self) -> TreeId { self.tree }
    pub const fn tree_sub(self) -> TreeSubId { self.tree_sub }
    pub const fn next_append_index(self) -> u64 { self.next_append_index }
}

/// State rows that can only be obtained from one exact sealed mutation graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmPreparedStateWriteSet {
    authority: AuthorityScope,
    coverage_plan: RealmNormalCommitCoveragePlan,
    prepared_payload_commitment: RealmPreparedPayloadCommitment,
    mutation_graph_digest: RealmImtMutationGraphDigest,
    rows: RealmPreparedStateRows,
    cursor_before: Vec<RealmImtCursorBeforeImage>,
}

impl RealmPreparedStateWriteSet {
    pub fn try_from_verified<F, Hash, Hasher>(
        prepared: &PsyPreparedRealmBlockStateUpdates<Hash>,
        graph: &SealedRealmImtMutationGraph<Hash, Hasher>,
        mut cursor_before: Vec<RealmImtCursorBeforeImage>,
    ) -> Result<Self, RealmFullCommitWriteSetError>
    where
        F: QFelt64,
        Hash: Q256BitHash,
    {
        let coverage_plan = RealmNormalCommitCoveragePlan::from_prepared(prepared);
        if !coverage_plan.invokes_state_update_branch() {
            return Err(RealmFullCommitWriteSetError::StateBranchRequired);
        }
        let rows = graph.expand_exact_prepared_rows::<F>(prepared)?;
        cursor_before.sort_unstable();
        if cursor_before.windows(2).any(|pair| {
            pair[0].tree == pair[1].tree && pair[0].tree_sub == pair[1].tree_sub
        }) {
            return Err(RealmFullCommitWriteSetError::DuplicateCursorBeforeImage);
        }

        let expected_pairs = rows
            .imt_leaves()
            .iter()
            .map(|mutation| match mutation {
                LogicalMutation::Put {
                    key: TypedTableKey::ImtLeaf { tree, tree_sub, .. },
                    ..
                } => Ok((*tree, *tree_sub)),
                _ => Err(RealmFullCommitWriteSetError::InvalidVerifiedImtLeaf),
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let actual_pairs = cursor_before
            .iter()
            .map(|cursor| (cursor.tree, cursor.tree_sub))
            .collect::<BTreeSet<_>>();
        if coverage_plan.invokes_imt_branch() {
            if expected_pairs != actual_pairs {
                return Err(RealmFullCommitWriteSetError::CursorBeforeImageCoverage);
            }
        } else if !rows.imt_leaves().is_empty() || !cursor_before.is_empty() {
            return Err(RealmFullCommitWriteSetError::UnexpectedImtInputs);
        }

        Ok(Self {
            authority: graph.authority(),
            coverage_plan,
            prepared_payload_commitment: rows.prepared_payload_commitment(),
            mutation_graph_digest: graph.digest(),
            rows,
            cursor_before,
        })
    }

    pub const fn authority(&self) -> AuthorityScope { self.authority }
    pub const fn coverage_plan(&self) -> RealmNormalCommitCoveragePlan {
        self.coverage_plan
    }
    pub const fn prepared_payload_commitment(&self) -> RealmPreparedPayloadCommitment {
        self.prepared_payload_commitment
    }
    pub const fn mutation_graph_digest(&self) -> RealmImtMutationGraphDigest {
        self.mutation_graph_digest
    }
    pub const fn rows(&self) -> &RealmPreparedStateRows { &self.rows }
    pub fn cursor_before(&self) -> &[RealmImtCursorBeforeImage] {
        &self.cursor_before
    }
}

/// Complete logical input for the physical 22-domain assembler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmFullCommitWriteSet {
    coverage_plan: RealmNormalCommitCoveragePlan,
    remaining: Vec<RealmCommitLogicalDomainBatch>,
    prepared_state: Option<RealmPreparedStateWriteSet>,
}

impl RealmFullCommitWriteSet {
    pub fn try_new<Hash>(
        prepared: &PsyPreparedRealmBlockStateUpdates<Hash>,
        mut remaining: Vec<RealmCommitLogicalDomainBatch>,
        prepared_state: Option<RealmPreparedStateWriteSet>,
    ) -> Result<Self, RealmFullCommitWriteSetError> {
        let coverage_plan = RealmNormalCommitCoveragePlan::from_prepared(prepared);
        if coverage_plan.has_ignored_prepared_payload() {
            return Err(RealmFullCommitWriteSetError::IgnoredPreparedPayload);
        }
        match (coverage_plan.invokes_state_update_branch(), &prepared_state) {
            (true, Some(state)) if state.coverage_plan == coverage_plan => {}
            (true, Some(_)) => {
                return Err(RealmFullCommitWriteSetError::PreparedStatePlanMismatch);
            }
            (true, None) => {
                return Err(RealmFullCommitWriteSetError::PreparedStateRequired);
            }
            (false, Some(_)) => {
                return Err(RealmFullCommitWriteSetError::UnexpectedPreparedState);
            }
            (false, None) => {}
        }

        remaining.sort_by_key(|batch| batch.domain);
        for pair in remaining.windows(2) {
            if pair[0].domain == pair[1].domain {
                return Err(RealmFullCommitWriteSetError::DuplicateDomain {
                    domain: pair[0].domain,
                });
            }
        }
        for batch in &remaining {
            if H22_BRANCH_EXACT_REALM_DOMAIN_SCOPE.contains(&batch.domain)
                || STATE_DOMAINS.contains(&batch.domain)
            {
                return Err(RealmFullCommitWriteSetError::ManagedDomainSupplied {
                    domain: batch.domain,
                });
            }
            if batch.mutations.is_empty() {
                return Err(RealmFullCommitWriteSetError::EmptyDomainBatch {
                    domain: batch.domain,
                });
            }
        }

        let expected = coverage_plan
            .domains()
            .filter(|domain| {
                !H22_BRANCH_EXACT_REALM_DOMAIN_SCOPE.contains(domain)
                    && !STATE_DOMAINS.contains(domain)
            })
            .collect::<Vec<_>>();
        let actual = remaining.iter().map(|batch| batch.domain).collect::<Vec<_>>();
        if actual != expected {
            if let Some(domain) = expected
                .iter()
                .copied()
                .find(|domain| actual.binary_search(domain).is_err())
            {
                return Err(RealmFullCommitWriteSetError::MissingDomain { domain });
            }
            let domain = actual
                .iter()
                .copied()
                .find(|domain| expected.binary_search(domain).is_err())
                .expect("different sorted domain sets have an unexpected member");
            return Err(RealmFullCommitWriteSetError::UnexpectedDomain { domain });
        }

        Ok(Self {
            coverage_plan,
            remaining,
            prepared_state,
        })
    }

    pub const fn coverage_plan(&self) -> RealmNormalCommitCoveragePlan {
        self.coverage_plan
    }
    pub fn remaining(&self) -> &[RealmCommitLogicalDomainBatch] { &self.remaining }
    pub const fn prepared_state(&self) -> Option<&RealmPreparedStateWriteSet> {
        self.prepared_state.as_ref()
    }
}

#[derive(Debug)]
pub enum RealmFullCommitWriteSetError {
    IgnoredPreparedPayload,
    PreparedStateRequired,
    PreparedStatePlanMismatch,
    UnexpectedPreparedState,
    StateBranchRequired,
    DuplicateCursorBeforeImage,
    CursorBeforeImageCoverage,
    UnexpectedImtInputs,
    InvalidVerifiedImtLeaf,
    DuplicateDomain { domain: RealmNormalCommitWriteDomain },
    ManagedDomainSupplied { domain: RealmNormalCommitWriteDomain },
    EmptyDomainBatch { domain: RealmNormalCommitWriteDomain },
    MissingDomain { domain: RealmNormalCommitWriteDomain },
    UnexpectedDomain { domain: RealmNormalCommitWriteDomain },
    Graph(RealmImtMutationGraphError),
}

impl From<RealmImtMutationGraphError> for RealmFullCommitWriteSetError {
    fn from(value: RealmImtMutationGraphError) -> Self { Self::Graph(value) }
}

impl fmt::Display for RealmFullCommitWriteSetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Realm full-commit write set: {self:?}")
    }
}

impl Error for RealmFullCommitWriteSetError {}

#[cfg(test)]
mod tests {
    use parth_core::{PHash, QCoreProcCheckpointUniqueId};
    use psy_data::prepared_block::realm::PsyPreparedRealmBlockStateUpdates;

    use super::*;
    use crate::store::typed::{
        CheckpointId, LatestInfoSlot, MutationValue, TypedTableKey,
        U64SingletonSlot,
    };

    fn prepared() -> PsyPreparedRealmBlockStateUpdates<PHash> {
        PsyPreparedRealmBlockStateUpdates {
            realm_id: 1,
            realm_sub_id: 2,
            unique_pending_id: 3,
            proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId::from(4_u128),
            old_realm_root: PHash::from_owned_32bytes([1; 32]),
            new_realm_root: PHash::from_owned_32bytes([1; 32]),
            update_global_user_tree_nodes_ffs: Vec::new(),
            update_user_contract_tree_nodes_ffs: Vec::new(),
            update_contract_state_tree_nodes_ffs: Vec::new(),
            update_user_leaves_ffs: Vec::new(),
            update_contract_state_imt_leaves_ffs: Vec::new(),
        }
    }

    fn mutation_for(domain: RealmNormalCommitWriteDomain) -> LogicalMutation {
        let checkpoint = CheckpointId::try_new(9).unwrap();
        let key = match domain {
            RealmNormalCommitWriteDomain::GlobalUserTopProofAtCheckpoint => {
                TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState)
            }
            RealmNormalCommitWriteDomain::CheckpointStateRoots => {
                TypedTableKey::CheckpointStateRoots(checkpoint)
            }
            RealmNormalCommitWriteDomain::CheckpointLeaf => {
                TypedTableKey::CheckpointLeaf(checkpoint)
            }
            RealmNormalCommitWriteDomain::GlobalCheckpointMerkle => {
                TypedTableKey::CheckpointLeaf(checkpoint)
            }
            RealmNormalCommitWriteDomain::CheckpointRootByHash
            | RealmNormalCommitWriteDomain::CheckpointRootByCheckpoint => {
                TypedTableKey::CheckpointLeaf(checkpoint)
            }
            RealmNormalCommitWriteDomain::L2BlockState => {
                TypedTableKey::L2BlockState(checkpoint)
            }
            RealmNormalCommitWriteDomain::LatestCheckpoint => {
                TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint)
            }
            RealmNormalCommitWriteDomain::LatestL2BlockState
            | RealmNormalCommitWriteDomain::RealmAuthorityObservation => {
                TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState)
            }
            other => panic!("unexpected non-state domain {other:?}"),
        };
        LogicalMutation::Put {
            key,
            value: MutationValue::PsyCanonicalBytes(vec![1]),
        }
    }

    fn complete_batches() -> Vec<RealmCommitLogicalDomainBatch> {
        RealmNormalCommitCoveragePlan::from_prepared(&prepared())
            .domains()
            .filter(|domain| {
                !H22_BRANCH_EXACT_REALM_DOMAIN_SCOPE.contains(domain)
                    && !STATE_DOMAINS.contains(domain)
            })
            .map(|domain| {
                RealmCommitLogicalDomainBatch::new(
                    domain,
                    vec![mutation_for(domain)],
                )
            })
            .collect()
    }

    #[test]
    fn logical_write_set_requires_every_non_h22_domain_once() {
        let complete = complete_batches();
        let write_set = RealmFullCommitWriteSet::try_new(
            &prepared(),
            complete.clone(),
            None,
        )
        .unwrap();
        assert_eq!(write_set.remaining().len(), 10);

        let mut missing = complete.clone();
        missing.retain(|batch| {
            batch.domain() != RealmNormalCommitWriteDomain::CheckpointLeaf
        });
        assert!(matches!(
            RealmFullCommitWriteSet::try_new(&prepared(), missing, None),
            Err(RealmFullCommitWriteSetError::MissingDomain {
                domain: RealmNormalCommitWriteDomain::CheckpointLeaf
            })
        ));

        let mut duplicate = complete;
        duplicate.push(duplicate[0].clone());
        assert!(matches!(
            RealmFullCommitWriteSet::try_new(&prepared(), duplicate, None),
            Err(RealmFullCommitWriteSetError::DuplicateDomain { .. })
        ));
    }
}
