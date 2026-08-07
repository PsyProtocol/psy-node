//! Exact semantic writer coverage for the current Realm `commit_state` path.
//!
//! This module deliberately models calls, not executable database mutations.
//! It is the driver-independent half of the gate that prevents a durable
//! PREPARED manifest from being published until every helper call has been
//! expanded into its physical Scylla mutations.  The legacy production path
//! may inspect this plan without changing its current write behaviour.

use psy_data::prepared_block::realm::PsyPreparedRealmBlockStateUpdates;

/// One semantic write domain reached by the current Realm `commit_state`
/// implementation.  Helper calls that fan out to two physical tables have two
/// variants, and two logical slots sharing one physical table remain distinct.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RealmNormalCommitWriteDomain {
    PendingToCheckpoint,
    CheckpointToPending,
    PendingToProc,
    ProcToPending,
    GlobalUserTopProofAtCheckpoint,
    RewardsTopProofAtPending,
    CheckpointStateRoots,
    CheckpointLeaf,
    GlobalCheckpointMerkle,
    CheckpointRootByHash,
    CheckpointRootByCheckpoint,
    L2BlockState,
    UserLeaf,
    ContractStateMerkle,
    ImtLeaf,
    ImtKeyIndex,
    ImtCursor,
    UserContractMerkle,
    GlobalUserMerkle,
    LatestCheckpoint,
    LatestL2BlockState,
    RealmAuthorityObservation,
}

impl RealmNormalCommitWriteDomain {
    /// Exhaustive stable ordering used by coverage resolution and evidence.
    pub const ALL: [Self; 22] = [
        Self::PendingToCheckpoint,
        Self::CheckpointToPending,
        Self::PendingToProc,
        Self::ProcToPending,
        Self::GlobalUserTopProofAtCheckpoint,
        Self::RewardsTopProofAtPending,
        Self::CheckpointStateRoots,
        Self::CheckpointLeaf,
        Self::GlobalCheckpointMerkle,
        Self::CheckpointRootByHash,
        Self::CheckpointRootByCheckpoint,
        Self::L2BlockState,
        Self::UserLeaf,
        Self::ContractStateMerkle,
        Self::ImtLeaf,
        Self::ImtKeyIndex,
        Self::ImtCursor,
        Self::UserContractMerkle,
        Self::GlobalUserMerkle,
        Self::LatestCheckpoint,
        Self::LatestL2BlockState,
        Self::RealmAuthorityObservation,
    ];

    const fn belongs_to_state_update_branch(self) -> bool {
        matches!(
            self,
            Self::UserLeaf
                | Self::ContractStateMerkle
                | Self::UserContractMerkle
                | Self::GlobalUserMerkle
        )
    }

    const fn belongs_to_imt_branch(self) -> bool {
        matches!(self, Self::ImtLeaf | Self::ImtKeyIndex | Self::ImtCursor)
    }

    /// Current production helper responsible for the domain.  Repeated
    /// symbols are intentional helper fan-out or distinct slots in one table.
    pub const fn writer_symbol(self) -> &'static str {
        match self {
            Self::PendingToCheckpoint => {
                "set_unique_pending_id_checkpoint_id_mapping"
            }
            Self::CheckpointToPending
            | Self::PendingToProc
            | Self::ProcToPending => {
                "set_checkpoint_id_to_unique_pending_id_mapping"
            }
            Self::GlobalUserTopProofAtCheckpoint => {
                "global_user_tree_set_top_tree_merkle_proof"
            }
            Self::RewardsTopProofAtPending => {
                "set_realm_rewards_tag_tree_top_proof_at_unique_pending_id"
            }
            Self::CheckpointStateRoots => "set_checkpoint_global_state_roots",
            Self::CheckpointLeaf => "set_checkpoint_leaf_data",
            Self::GlobalCheckpointMerkle => {
                "checkpoint_tree_injest_merkle_proof"
            }
            Self::CheckpointRootByHash | Self::CheckpointRootByCheckpoint => {
                "set_checkpoint_root_hash_to_id_mapping"
            }
            Self::L2BlockState => "set_l2_block_state",
            Self::UserLeaf => "set_user_leaves_ffs",
            Self::ContractStateMerkle => {
                "contract_state_tree_set_nodes_ffs"
            }
            Self::ImtLeaf | Self::ImtKeyIndex | Self::ImtCursor => {
                "contract_state_imt_set_leaves_ffs"
            }
            Self::UserContractMerkle => {
                "user_contract_tree_set_nodes_ffs"
            }
            Self::GlobalUserMerkle => "global_user_tree_set_nodes_ffs",
            Self::LatestCheckpoint => "set_latest_checkpoint_id",
            Self::LatestL2BlockState => "set_l2_latest_block_state",
            Self::RealmAuthorityObservation => {
                "set_realm_authority_observation"
            }
        }
    }
}

/// A prepared field that the current production control flow will not write.
/// This is evidence for the future fail-closed durable path; observing it does
/// not alter legacy production behaviour in this integration slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IgnoredRealmPreparedField {
    GlobalUserTreeNodes,
    UserContractTreeNodes,
    ContractStateTreeNodes,
    ContractStateImtLeaves,
}

impl IgnoredRealmPreparedField {
    const ALL: [Self; 4] = [
        Self::GlobalUserTreeNodes,
        Self::UserContractTreeNodes,
        Self::ContractStateTreeNodes,
        Self::ContractStateImtLeaves,
    ];
}

/// The exact branches the current production implementation will execute for
/// one prepared Realm update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmNormalCommitCoveragePlan {
    invokes_state_update_branch: bool,
    invokes_imt_branch: bool,
    ignored_prepared_fields: [bool; 4],
}

impl RealmNormalCommitCoveragePlan {
    /// Derive coverage from the same branch predicates used by `commit_state`.
    /// No payload parsing or database access occurs here.
    pub fn from_prepared<Hash>(
        prepared: &PsyPreparedRealmBlockStateUpdates<Hash>,
    ) -> Self {
        let invokes_state_update_branch =
            !prepared.update_user_leaves_ffs.is_empty();
        let invokes_imt_branch = invokes_state_update_branch
            && !prepared.update_contract_state_imt_leaves_ffs.is_empty();
        let ignored_prepared_fields = if invokes_state_update_branch {
            [false; 4]
        } else {
            [
                !prepared.update_global_user_tree_nodes_ffs.is_empty(),
                !prepared.update_user_contract_tree_nodes_ffs.is_empty(),
                !prepared.update_contract_state_tree_nodes_ffs.is_empty(),
                !prepared.update_contract_state_imt_leaves_ffs.is_empty(),
            ]
        };
        Self {
            invokes_state_update_branch,
            invokes_imt_branch,
            ignored_prepared_fields,
        }
    }

    pub const fn invokes_state_update_branch(self) -> bool {
        self.invokes_state_update_branch
    }

    pub const fn invokes_imt_branch(self) -> bool {
        self.invokes_imt_branch
    }

    pub fn domains(
        self,
    ) -> impl Iterator<Item = RealmNormalCommitWriteDomain> {
        RealmNormalCommitWriteDomain::ALL
            .into_iter()
            .filter(move |domain| {
                (!domain.belongs_to_state_update_branch()
                    || self.invokes_state_update_branch)
                    && (!domain.belongs_to_imt_branch()
                        || self.invokes_imt_branch)
            })
    }

    pub fn ignored_prepared_fields(
        self,
    ) -> impl Iterator<Item = IgnoredRealmPreparedField> {
        IgnoredRealmPreparedField::ALL
            .into_iter()
            .zip(self.ignored_prepared_fields)
            .filter_map(|(field, ignored)| ignored.then_some(field))
    }

    pub fn has_ignored_prepared_payload(self) -> bool {
        self.ignored_prepared_fields.into_iter().any(|ignored| ignored)
    }

    pub fn ignored_prepared_field_count(self) -> usize {
        self.ignored_prepared_fields
            .into_iter()
            .filter(|ignored| *ignored)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use parth_core::{
        PHash, QCoreProcCheckpointUniqueId,
        protocol::core_types::Q256BitHash,
    };

    use super::*;

    fn prepared() -> PsyPreparedRealmBlockStateUpdates<PHash> {
        PsyPreparedRealmBlockStateUpdates {
            realm_id: 1,
            realm_sub_id: 2,
            unique_pending_id: 3,
            proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId::from(4_u128),
            old_realm_root: PHash::from_owned_32bytes([1; 32]),
            new_realm_root: PHash::from_owned_32bytes([2; 32]),
            update_global_user_tree_nodes_ffs: vec![1],
            update_user_contract_tree_nodes_ffs: vec![2],
            update_contract_state_tree_nodes_ffs: vec![3],
            update_user_leaves_ffs: vec![4],
            update_contract_state_imt_leaves_ffs: vec![5],
        }
    }

    #[test]
    fn full_state_and_imt_path_has_all_22_semantic_domains() {
        let plan = RealmNormalCommitCoveragePlan::from_prepared(&prepared());
        assert!(plan.invokes_state_update_branch());
        assert!(plan.invokes_imt_branch());
        assert_eq!(
            plan.domains().collect::<Vec<_>>(),
            RealmNormalCommitWriteDomain::ALL
        );
        assert!(!plan.has_ignored_prepared_payload());
    }

    #[test]
    fn state_without_imt_has_exact_19_domains() {
        let mut prepared = prepared();
        prepared.update_contract_state_imt_leaves_ffs.clear();
        let plan = RealmNormalCommitCoveragePlan::from_prepared(&prepared);
        let domains = plan.domains().collect::<Vec<_>>();
        assert_eq!(domains.len(), 19);
        assert!(!domains.contains(&RealmNormalCommitWriteDomain::ImtLeaf));
        assert!(!domains.contains(&RealmNormalCommitWriteDomain::ImtKeyIndex));
        assert!(!domains.contains(&RealmNormalCommitWriteDomain::ImtCursor));
    }

    #[test]
    fn no_state_branch_has_exact_15_mandatory_domains() {
        let mut prepared = prepared();
        prepared.update_global_user_tree_nodes_ffs.clear();
        prepared.update_user_contract_tree_nodes_ffs.clear();
        prepared.update_contract_state_tree_nodes_ffs.clear();
        prepared.update_user_leaves_ffs.clear();
        prepared.update_contract_state_imt_leaves_ffs.clear();
        let plan = RealmNormalCommitCoveragePlan::from_prepared(&prepared);
        assert_eq!(plan.domains().count(), 15);
        assert!(!plan.invokes_state_update_branch());
        assert!(!plan.invokes_imt_branch());
        assert!(!plan.has_ignored_prepared_payload());
    }

    #[test]
    fn payload_hidden_behind_user_leaf_branch_is_reported() {
        let mut prepared = prepared();
        prepared.update_user_leaves_ffs.clear();
        let plan = RealmNormalCommitCoveragePlan::from_prepared(&prepared);
        assert_eq!(plan.domains().count(), 15);
        assert_eq!(
            plan.ignored_prepared_fields().collect::<Vec<_>>(),
            vec![
                IgnoredRealmPreparedField::GlobalUserTreeNodes,
                IgnoredRealmPreparedField::UserContractTreeNodes,
                IgnoredRealmPreparedField::ContractStateTreeNodes,
                IgnoredRealmPreparedField::ContractStateImtLeaves,
            ]
        );
    }
}
