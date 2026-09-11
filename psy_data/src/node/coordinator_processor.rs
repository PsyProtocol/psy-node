use parth_core::{QCoreProcCheckpointUniqueId, crypto::hash::traits::{FieldQHasher, QFieldHashable}, felt::{QFelt, QFelt64}, generic_traits::psy_debug_printable::PsyDebugPrintable, node::realm_identifier::QRealmIdentifier, protocol::core_types::{QFHashBase, QHashBase}};

use crate::{protocol::checkpoint_transition_hash::CheckpointStateHashTransition, v1::qdata::{checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, PQEDCheckpointLeafStats, QEDL2BlockState}, populated_checkpoint::PsyCheckpointLeafPopulated}};

#[pderive::serialize_copy_f_hash]
pub struct CoordinatorProcessorLastCommittedState<F, Hash> {
    pub l2_state: QEDL2BlockState,
    pub checkpoint_leaf_stats: PQEDCheckpointLeafStats<F, Hash>,
    pub checkpoint_leaf: PQEDCheckpointLeaf<F, Hash>,
    pub checkpoint_state_roots: PQEDCheckpointGlobalStateRoots<Hash>,
    pub checkpoint_state_transition: CheckpointStateHashTransition<Hash>,
    pub checkpoint_root: Hash,
    pub checkpoint_leaf_hash: Hash,
    pub last_chain_hash: Hash,
}


impl<F: QFelt, Hash: QHashBase> PsyDebugPrintable for CoordinatorProcessorLastCommittedState<F, Hash> {
    fn psy_debug_print(&self) -> String {
        format!("{:#?}", self)
        
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> CoordinatorProcessorLastCommittedState<F, Hash> {
    pub fn update_for_block<Hasher: FieldQHasher<F, Hash>>(
        &mut self,
        l2_state: QEDL2BlockState,
        populated_leaf: PsyCheckpointLeafPopulated<F, Hash>,
        checkpoint_state_transition: CheckpointStateHashTransition<Hash>,
    ) -> anyhow::Result<()> {
        let expected_leaf_hash = populated_leaf.qfhash::<Hasher>();
        if expected_leaf_hash != checkpoint_state_transition.new_checkpoint_leaf_hash {
            return Err(anyhow::anyhow!(
                "Populated checkpoint leaf hash does not match expected hash. Expected: {:?}, Actual: {:?}",
                checkpoint_state_transition.new_checkpoint_leaf_hash,
                expected_leaf_hash
            ));
        }
        self.l2_state = l2_state;
        self.checkpoint_leaf_stats = populated_leaf.stats;
        self.checkpoint_leaf = populated_leaf.to_checkpoint_leaf::<Hasher>();
        self.checkpoint_state_roots = populated_leaf.global_state_roots;
        self.checkpoint_state_transition = checkpoint_state_transition;
        self.checkpoint_root = checkpoint_state_transition.new_checkpoint_tree_root;
        self.checkpoint_leaf_hash = expected_leaf_hash;
        Ok(())
    }
    pub fn new_from_minimal<Hasher: FieldQHasher<F, Hash>>(
        l2_state: QEDL2BlockState,
        populated_leaf: PsyCheckpointLeafPopulated<F, Hash>,
        checkpoint_state_transition: CheckpointStateHashTransition<Hash>,
        last_chain_hash: Hash,
    ) -> anyhow::Result<Self> {
        let expected_leaf_hash = populated_leaf.qfhash::<Hasher>();
        if expected_leaf_hash != checkpoint_state_transition.new_checkpoint_leaf_hash {
            return Err(anyhow::anyhow!(
                "Populated checkpoint leaf hash does not match expected hash. Expected: {:?}, Actual: {:?}",
                checkpoint_state_transition.new_checkpoint_leaf_hash,
                expected_leaf_hash
            ));
        }
        Ok(Self {
            l2_state,
            checkpoint_leaf_stats: populated_leaf.stats,
            checkpoint_leaf: populated_leaf.to_checkpoint_leaf::<Hasher>(),
            checkpoint_state_roots: populated_leaf.global_state_roots,
            checkpoint_state_transition,
            checkpoint_root: checkpoint_state_transition.new_checkpoint_tree_root,
            checkpoint_leaf_hash: expected_leaf_hash,
            last_chain_hash,
        })
    }
}

impl<F: Copy, Hash: Copy> CoordinatorProcessorLastCommittedState<F, Hash> {
    pub fn get_last_committed_populated_checkpoint(&self) -> PsyCheckpointLeafPopulated<F, Hash> {
        PsyCheckpointLeafPopulated {
            global_state_roots: self.checkpoint_state_roots,
            stats: self.checkpoint_leaf_stats,
        }
    }
}


#[pderive::serialize_copy]
pub struct CoordinatorProcessorIdState {
    pub realm_identifier: QRealmIdentifier,
    pub realm_id_u64: u64,
    pub realm_sub_id_u64: u64,


    pub checkpoint_id: u64,
    pub next_checkpoint_id: u64,
    
    pub unique_pending_id: u64,
    pub proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,

    pub gathering_unique_pending_id: u64,
    pub gathering_proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
}

#[cfg(test)]
mod behavior_tests {
    use super::*;
    use parth_core::{pgoldilocks::PoseidonHasher, utils::QPGenRandom, PF, PHash};

    fn hash() -> PHash {
        PHash::qp_rand_gen()
    }

    fn transition_matching(leaf: &PsyCheckpointLeafPopulated<PF, PHash>) -> CheckpointStateHashTransition<PHash> {
        CheckpointStateHashTransition {
            old_checkpoint_tree_root: hash(),
            new_checkpoint_tree_root: hash(),
            old_checkpoint_leaf_hash: hash(),
            new_checkpoint_leaf_hash: leaf.qfhash::<PoseidonHasher>(),
        }
    }

    fn mismatching_transition() -> CheckpointStateHashTransition<PHash> {
        CheckpointStateHashTransition {
            old_checkpoint_tree_root: hash(),
            new_checkpoint_tree_root: hash(),
            old_checkpoint_leaf_hash: hash(),
            new_checkpoint_leaf_hash: PHash::from_values(0, 0, 0, 1),
        }
    }

    #[test]
    fn new_from_minimal_rejects_mismatched_leaf_hash() {
        let populated = PsyCheckpointLeafPopulated::<PF, PHash>::qp_rand_gen();
        let result = CoordinatorProcessorLastCommittedState::<PF, PHash>::new_from_minimal::<PoseidonHasher>(
            QEDL2BlockState::qp_rand_gen(),
            populated,
            mismatching_transition(),
            hash(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn new_from_minimal_captures_committed_checkpoint() {
        let populated = PsyCheckpointLeafPopulated::<PF, PHash>::qp_rand_gen();
        let transition = transition_matching(&populated);
        let l2_state = QEDL2BlockState::qp_rand_gen();
        let last_chain_hash = hash();

        let state = CoordinatorProcessorLastCommittedState::<PF, PHash>::new_from_minimal::<PoseidonHasher>(
            l2_state,
            populated.clone(),
            transition,
            last_chain_hash,
        )
        .unwrap();

        assert_eq!(state.l2_state, l2_state);
        assert_eq!(state.checkpoint_leaf_stats, populated.stats);
        assert_eq!(state.checkpoint_leaf, populated.to_checkpoint_leaf::<PoseidonHasher>());
        assert_eq!(state.checkpoint_state_roots, populated.global_state_roots);
        assert_eq!(state.checkpoint_state_transition, transition);
        assert_eq!(state.checkpoint_root, transition.new_checkpoint_tree_root);
        assert_eq!(state.checkpoint_leaf_hash, populated.qfhash::<PoseidonHasher>());
        assert_eq!(state.last_chain_hash, last_chain_hash);
        assert_eq!(state.get_last_committed_populated_checkpoint(), populated);
    }

    #[test]
    fn update_for_block_advances_state_and_rejects_mismatches() {
        let first_leaf = PsyCheckpointLeafPopulated::<PF, PHash>::qp_rand_gen();
        let mut state = CoordinatorProcessorLastCommittedState::<PF, PHash>::new_from_minimal::<PoseidonHasher>(
            QEDL2BlockState::qp_rand_gen(),
            first_leaf,
            transition_matching(&first_leaf),
            hash(),
        )
        .unwrap();

        let next_leaf = PsyCheckpointLeafPopulated::<PF, PHash>::qp_rand_gen();
        let next_transition = transition_matching(&next_leaf);
        let next_l2 = QEDL2BlockState::qp_rand_gen();
        state.update_for_block::<PoseidonHasher>(next_l2, next_leaf.clone(), next_transition).unwrap();

        assert_eq!(state.l2_state, next_l2);
        assert_eq!(state.checkpoint_leaf_stats, next_leaf.stats);
        assert_eq!(state.checkpoint_state_transition, next_transition);
        assert_eq!(state.checkpoint_root, next_transition.new_checkpoint_tree_root);
        assert_eq!(state.checkpoint_leaf_hash, next_leaf.qfhash::<PoseidonHasher>());
        assert_eq!(state.get_last_committed_populated_checkpoint(), next_leaf);

        // A mismatched transition must be rejected without mutating the state.
        let committed_root = state.checkpoint_root;
        let stale_leaf = PsyCheckpointLeafPopulated::<PF, PHash>::qp_rand_gen();
        assert!(state
            .update_for_block::<PoseidonHasher>(
                QEDL2BlockState::qp_rand_gen(),
                stale_leaf,
                mismatching_transition(),
            )
            .is_err());
        assert_eq!(state.checkpoint_root, committed_root);
    }

    #[test]
    fn debug_print_renders_the_committed_state() {
        let leaf = PsyCheckpointLeafPopulated::<PF, PHash>::qp_rand_gen();
        let state = CoordinatorProcessorLastCommittedState::<PF, PHash>::new_from_minimal::<PoseidonHasher>(
            QEDL2BlockState::qp_rand_gen(),
            leaf,
            transition_matching(&leaf),
            hash(),
        )
        .unwrap();

        let printed = state.psy_debug_print();
        assert!(printed.contains("CoordinatorProcessorLastCommittedState"));
        assert!(!printed.is_empty());
    }

    #[test]
    fn id_state_round_trips_through_serde() {
        let id_state = CoordinatorProcessorIdState {
            realm_identifier: QRealmIdentifier::new(5, 6),
            realm_id_u64: 5,
            realm_sub_id_u64: 6,
            checkpoint_id: 10,
            next_checkpoint_id: 11,
            unique_pending_id: 12,
            proc_checkpoint_unique_id: 13,
            gathering_unique_pending_id: 14,
            gathering_proc_checkpoint_unique_id: 15,
        };
        let encoded = serde_json::to_vec(&id_state).unwrap();
        let decoded: CoordinatorProcessorIdState = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, id_state);
    }
}
