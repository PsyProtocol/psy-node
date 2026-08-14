//! Exact semantic coverage for the current Coordinator `commit_state` path.
//!
//! This module models the complete logical writer surface without owning a
//! database or authorizing a mutation.  The timestamped Coordinator writer
//! must expand every selected domain into physical mutations before it may
//! seal a manifest or publish a canonical head.

use psy_data::prepared_block::coordinator::PsyPreparedCoordinatorBlockStateUpdates;

/// One semantic write domain reached by a normal Coordinator commit.
///
/// Helper calls which fan out to two physical tables remain distinct domains,
/// and compatibility singletons are intentionally separate from their
/// checkpoint-keyed source rows.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CoordinatorNormalCommitWriteDomain {
    CheckpointZkProof,
    PendingToCheckpoint,
    CheckpointToPending,
    PendingToProc,
    ProcToPending,
    ContractLeaf,
    ContractCodeDefinition,
    ContractStateTreeHeight,
    ContractFunctionMerkle,
    GlobalContractMerkle,
    UserPublicKey,
    PublicKeyToUser,
    UserRegistrationMerkle,
    GlobalUserMerkle,
    RealmRewardNode,
    CheckpointStateRoots,
    L2BlockState,
    LatestL2BlockState,
    CheckpointLeaf,
    GlobalCheckpointMerkle,
    CheckpointRootByHash,
    CheckpointRootByCheckpoint,
    LatestCheckpoint,
}

impl CoordinatorNormalCommitWriteDomain {
    pub const ALL: [Self; 23] = [
        Self::CheckpointZkProof,
        Self::PendingToCheckpoint,
        Self::CheckpointToPending,
        Self::PendingToProc,
        Self::ProcToPending,
        Self::ContractLeaf,
        Self::ContractCodeDefinition,
        Self::ContractStateTreeHeight,
        Self::ContractFunctionMerkle,
        Self::GlobalContractMerkle,
        Self::UserPublicKey,
        Self::PublicKeyToUser,
        Self::UserRegistrationMerkle,
        Self::GlobalUserMerkle,
        Self::RealmRewardNode,
        Self::CheckpointStateRoots,
        Self::L2BlockState,
        Self::LatestL2BlockState,
        Self::CheckpointLeaf,
        Self::GlobalCheckpointMerkle,
        Self::CheckpointRootByHash,
        Self::CheckpointRootByCheckpoint,
        Self::LatestCheckpoint,
    ];

    const fn belongs_to_contract_branch(self) -> bool {
        matches!(
            self,
            Self::ContractLeaf
                | Self::ContractCodeDefinition
                | Self::ContractStateTreeHeight
                | Self::ContractFunctionMerkle
                | Self::GlobalContractMerkle
        )
    }

    const fn belongs_to_registration_branch(self) -> bool {
        matches!(
            self,
            Self::UserPublicKey | Self::PublicKeyToUser | Self::UserRegistrationMerkle
        )
    }

    const fn belongs_to_global_user_branch(self) -> bool {
        matches!(self, Self::GlobalUserMerkle)
    }

    const fn belongs_to_reward_branch(self) -> bool {
        matches!(self, Self::RealmRewardNode)
    }

    /// Existing production helper responsible for this semantic domain.
    pub const fn writer_symbol(self) -> &'static str {
        match self {
            Self::CheckpointZkProof => "set_verifiable_checkpoint_state_transition_and_zkp",
            Self::PendingToCheckpoint => "set_unique_pending_id_checkpoint_id_mapping",
            Self::CheckpointToPending | Self::PendingToProc | Self::ProcToPending => {
                "set_checkpoint_id_to_unique_pending_id_mapping"
            }
            Self::ContractLeaf => "set_contract_leaves_ffs",
            Self::ContractCodeDefinition => "set_many_contract_code_definitions",
            Self::ContractStateTreeHeight => "set_contract_tree_heights",
            Self::ContractFunctionMerkle => "contract_function_tree_set_nodes_ffs",
            Self::GlobalContractMerkle => "global_contract_tree_set_nodes_ffs",
            Self::UserPublicKey => "set_zk_public_keys_ffs",
            Self::PublicKeyToUser => "set_public_key_for_user_ids_ffs",
            Self::UserRegistrationMerkle => "user_registration_tree_set_nodes_ffs",
            Self::GlobalUserMerkle => "global_user_tree_set_nodes_ffs",
            Self::RealmRewardNode => "set_realm_guta_reward_tree_node_keys_ffs",
            Self::CheckpointStateRoots => "set_checkpoint_global_state_roots",
            Self::L2BlockState => "set_l2_block_state",
            Self::LatestL2BlockState => "set_l2_latest_block_state",
            Self::CheckpointLeaf => "set_checkpoint_leaf_data",
            Self::GlobalCheckpointMerkle => "checkpoint_tree_set_leaf_hash",
            Self::CheckpointRootByHash | Self::CheckpointRootByCheckpoint => {
                "set_checkpoint_root_hash_to_id_mapping"
            }
            Self::LatestCheckpoint => "set_latest_checkpoint_id",
        }
    }
}

/// Payload which the legacy implementation silently ignores because its
/// enclosing branch predicate is false.  The branch-exact writer must reject
/// such an update instead of publishing a partial state transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IgnoredCoordinatorPreparedField {
    ContractCodeDefinitions,
    ContractFunctionTreeNodes,
    GlobalContractTreeNodes,
    PublicKeyHashProjection,
    UserRegistrationTreeNodes,
}

impl IgnoredCoordinatorPreparedField {
    const ALL: [Self; 5] = [
        Self::ContractCodeDefinitions,
        Self::ContractFunctionTreeNodes,
        Self::GlobalContractTreeNodes,
        Self::PublicKeyHashProjection,
        Self::UserRegistrationTreeNodes,
    ];
}

/// Exact branch predicates selected by one prepared Coordinator update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoordinatorNormalCommitCoveragePlan {
    invokes_contract_branch: bool,
    invokes_registration_branch: bool,
    invokes_global_user_branch: bool,
    invokes_reward_branch: bool,
    ignored_prepared_fields: [bool; 5],
}

impl CoordinatorNormalCommitCoveragePlan {
    pub fn from_prepared<F, Hash>(
        prepared: &PsyPreparedCoordinatorBlockStateUpdates<F, Hash>,
    ) -> Self {
        let invokes_contract_branch = !prepared.new_contract_leaves_ffs.is_empty();
        let invokes_registration_branch = !prepared.new_user_public_keys_ffs.is_empty();
        let invokes_global_user_branch = !prepared.update_global_user_tree_nodes_ffs.is_empty();
        let invokes_reward_branch =
            !prepared.new_realm_guta_reward_tree_node_keys_ffs.is_empty();
        Self {
            invokes_contract_branch,
            invokes_registration_branch,
            invokes_global_user_branch,
            invokes_reward_branch,
            ignored_prepared_fields: [
                !invokes_contract_branch && !prepared.new_contract_code_definitions.is_empty(),
                !invokes_contract_branch
                    && !prepared.update_contract_function_tree_nodes_ffs.is_empty(),
                !invokes_contract_branch
                    && !prepared.update_global_contract_tree_nodes_ffs.is_empty(),
                !invokes_registration_branch
                    && !prepared.new_public_key_hash_to_user_id_rows_ffs.is_empty(),
                !invokes_registration_branch
                    && !prepared.update_user_registration_tree_nodes_ffs.is_empty(),
            ],
        }
    }

    pub const fn invokes_contract_branch(self) -> bool {
        self.invokes_contract_branch
    }

    pub const fn invokes_registration_branch(self) -> bool {
        self.invokes_registration_branch
    }

    pub const fn invokes_global_user_branch(self) -> bool {
        self.invokes_global_user_branch
    }

    pub const fn invokes_reward_branch(self) -> bool {
        self.invokes_reward_branch
    }

    pub fn domains(self) -> impl Iterator<Item = CoordinatorNormalCommitWriteDomain> {
        CoordinatorNormalCommitWriteDomain::ALL
            .into_iter()
            .filter(move |domain| {
                (!domain.belongs_to_contract_branch() || self.invokes_contract_branch)
                    && (!domain.belongs_to_registration_branch()
                        || self.invokes_registration_branch)
                    && (!domain.belongs_to_global_user_branch()
                        || self.invokes_global_user_branch)
                    && (!domain.belongs_to_reward_branch() || self.invokes_reward_branch)
            })
    }

    pub fn ignored_prepared_fields(
        self,
    ) -> impl Iterator<Item = IgnoredCoordinatorPreparedField> {
        IgnoredCoordinatorPreparedField::ALL
            .into_iter()
            .zip(self.ignored_prepared_fields)
            .filter_map(|(field, ignored)| ignored.then_some(field))
    }

    pub fn has_ignored_prepared_payload(self) -> bool {
        self.ignored_prepared_fields.into_iter().any(|ignored| ignored)
    }
}

#[cfg(test)]
mod tests {
    use parth_core::{
        PF, PHash,
        crypto::hash::{merkle_proof::DeltaMerkleProofCore, traits::ZeroableHash},
    };
    use psy_data::{
        prepared_block::common::PsyCoordinatorPendingCheckpointBase,
        v1::qdata::{
            checkpoint::{
                PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeafStats, QEDL2BlockState,
            },
            populated_checkpoint::PsyCheckpointLeafPopulated,
        },
    };

    use super::*;

    fn prepared() -> PsyPreparedCoordinatorBlockStateUpdates<PF, PHash> {
        let leaf = PsyCheckpointLeafPopulated {
            global_state_roots: PQEDCheckpointGlobalStateRoots {
                contract_tree_root: PHash::get_zero_value(),
                deposit_tree_root: PHash::get_zero_value(),
                user_tree_root: PHash::get_zero_value(),
                withdrawal_tree_root: PHash::get_zero_value(),
                user_registration_tree_root: PHash::get_zero_value(),
            },
            stats: PQEDCheckpointLeafStats::get_empty_stats(),
        };
        let block_state = QEDL2BlockState {
            checkpoint_id: 1,
            next_add_withdrawal_id: 0,
            next_process_withdrawal_id: 0,
            next_deposit_id: 0,
            total_deposits_claimed_epoch: 0,
            next_user_id: 0,
            end_balance: 0,
            next_contract_id: 0,
        };
        let base = PsyCoordinatorPendingCheckpointBase {
            block_state,
            checkpoint_leaf: leaf,
            checkpoint_leaf_hash: PHash::get_zero_value(),
            checkpoint_tree_root: PHash::get_zero_value(),
        };
        PsyPreparedCoordinatorBlockStateUpdates {
            coordinator_id: 0,
            checkpoint_id: 1,
            unique_pending_id: 2,
            proc_checkpoint_unique_id: 3,
            old_base: base.clone(),
            new_base: base,
            update_global_contract_tree_nodes_ffs: Vec::new(),
            update_contract_function_tree_nodes_ffs: Vec::new(),
            new_contract_leaves_ffs: Vec::new(),
            new_contract_code_definitions: Vec::new(),
            update_user_registration_tree_nodes_ffs: Vec::new(),
            new_user_public_keys_ffs: Vec::new(),
            new_public_key_hash_to_user_id_rows_ffs: Vec::new(),
            update_global_user_tree_nodes_ffs: Vec::new(),
            new_realm_guta_reward_tree_node_keys_ffs: Vec::new(),
            checkpoint_tree_update_proof: DeltaMerkleProofCore {
                index: 1,
                old_value: PHash::get_zero_value(),
                new_value: PHash::get_zero_value(),
                siblings: Vec::new(),
                old_root: PHash::get_zero_value(),
                new_root: PHash::get_zero_value(),
            },
        }
    }

    #[test]
    fn empty_update_still_covers_all_thirteen_always_written_domains() {
        let plan = CoordinatorNormalCommitCoveragePlan::from_prepared(&prepared());
        assert_eq!(plan.domains().count(), 13);
        assert!(!plan.has_ignored_prepared_payload());
    }

    #[test]
    fn all_branches_cover_all_twenty_three_domains() {
        let mut prepared = prepared();
        prepared.new_contract_leaves_ffs.push(1);
        prepared.new_user_public_keys_ffs.push(2);
        prepared.update_global_user_tree_nodes_ffs.push(3);
        prepared.new_realm_guta_reward_tree_node_keys_ffs.push(4);
        let plan = CoordinatorNormalCommitCoveragePlan::from_prepared(&prepared);
        assert_eq!(
            plan.domains().collect::<Vec<_>>(),
            CoordinatorNormalCommitWriteDomain::ALL
        );
        assert!(!plan.has_ignored_prepared_payload());
    }

    #[test]
    fn hidden_contract_and_registration_payload_is_rejected_by_future_writer() {
        let mut prepared = prepared();
        prepared.update_contract_function_tree_nodes_ffs.push(1);
        prepared.update_global_contract_tree_nodes_ffs.push(2);
        prepared.new_public_key_hash_to_user_id_rows_ffs.push(3);
        prepared.update_user_registration_tree_nodes_ffs.push(4);
        let plan = CoordinatorNormalCommitCoveragePlan::from_prepared(&prepared);
        assert!(plan.has_ignored_prepared_payload());
        assert_eq!(plan.ignored_prepared_fields().count(), 4);
    }

    #[test]
    fn every_domain_has_an_explicit_legacy_writer_mapping() {
        assert_eq!(CoordinatorNormalCommitWriteDomain::ALL.len(), 23);
        assert!(CoordinatorNormalCommitWriteDomain::ALL
            .into_iter()
            .all(|domain| !domain.writer_symbol().is_empty()));
    }
}
