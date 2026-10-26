use parth_core::{
    crypto::hash::{merkle_proof::DeltaMerkleProofCore, traits::MerkleHasher},
    QCoreProcCheckpointUniqueId,
};

use crate::{
    prepared_block::common::PsyCoordinatorPendingCheckpointBase,
    protocol::{
        checkpoint_transition_hash::{CheckpointStateHashTransition, CheckpointStateTransitionPublicInputs},
        verifiable_checkpoint_transition::PsyVerifiableCheckpointTransition,
    },
    v1::qdata::contract::ContractCodeDefinitionWithContractId,
};

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct PsyPreparedCoordinatorBlockStateUpdates<F, Hash> {
    pub coordinator_id: u64,
    pub checkpoint_id: u64,
    pub unique_pending_id: u64,
    pub proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
    pub old_base: PsyCoordinatorPendingCheckpointBase<F, Hash>,
    pub new_base: PsyCoordinatorPendingCheckpointBase<F, Hash>,

    pub update_global_contract_tree_nodes_ffs: Vec<u8>,
    pub update_contract_function_tree_nodes_ffs: Vec<u8>,
    pub new_contract_leaves_ffs: Vec<u8>,
    pub new_contract_code_definitions: Vec<ContractCodeDefinitionWithContractId>,

    pub update_user_registration_tree_nodes_ffs: Vec<u8>,
    pub new_user_public_keys_ffs: Vec<u8>,
    pub new_public_key_hash_to_user_id_rows_ffs: Vec<u8>,

    pub update_global_user_tree_nodes_ffs: Vec<u8>,
    pub new_realm_guta_reward_tree_node_keys_ffs: Vec<u8>,

    pub checkpoint_tree_update_proof: DeltaMerkleProofCore<Hash>,
}

impl<F: Copy + PartialEq, Hash: Copy + PartialEq> PsyPreparedCoordinatorBlockStateUpdates<F, Hash> {
    pub fn get_public_inputs_verifiable_state_transition(
        &self,
        genesis_checkpoint_state_transition_hash: Hash,
        checkpoint_state_transition_circuit_fingerprint: Hash,
    ) -> PsyVerifiableCheckpointTransition<F, Hash> {
        PsyVerifiableCheckpointTransition {
            state_transition: CheckpointStateTransitionPublicInputs {
                checkpoint_transition: CheckpointStateHashTransition {
                    old_checkpoint_tree_root: self.old_base.checkpoint_tree_root,
                    new_checkpoint_tree_root: self.new_base.checkpoint_tree_root,
                    old_checkpoint_leaf_hash: self.old_base.checkpoint_leaf_hash,
                    new_checkpoint_leaf_hash: self.new_base.checkpoint_leaf_hash,
                },
                genesis_checkpoint_state_transition_hash,
                checkpoint_state_transition_circuit_fingerprint,
            },
            checkpoint_leaf: self.new_base.checkpoint_leaf,
        }
    }
    pub fn get_checkpoint_state_transition_hash<Hasher: MerkleHasher<Hash>>(
        &self,
    ) -> Hash {
        CheckpointStateHashTransition {
            old_checkpoint_tree_root: self.old_base.checkpoint_tree_root,
            new_checkpoint_tree_root: self.new_base.checkpoint_tree_root,
            old_checkpoint_leaf_hash: self.old_base.checkpoint_leaf_hash,
            new_checkpoint_leaf_hash: self.new_base.checkpoint_leaf_hash,
        }
        .get_hash::<Hasher>()
    }
    pub fn get_checkpoint_transition_public_inputs_hash<Hasher: MerkleHasher<Hash>>(
        &self,
        genesis_checkpoint_state_transition_hash: Hash,
        checkpoint_state_transition_circuit_fingerprint: Hash,
    ) -> Hash {
        CheckpointStateTransitionPublicInputs {
            checkpoint_transition: CheckpointStateHashTransition {
                old_checkpoint_tree_root: self.old_base.checkpoint_tree_root,
                new_checkpoint_tree_root: self.new_base.checkpoint_tree_root,
                old_checkpoint_leaf_hash: self.old_base.checkpoint_leaf_hash,
                new_checkpoint_leaf_hash: self.new_base.checkpoint_leaf_hash,
            },
            genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint,
        }
        .get_public_inputs_hash_no_rewards_tag::<Hasher>()
    }
}

#[cfg(test)]
mod behavior_tests {
    use super::*;
    use parth_core::{pgoldilocks::PoseidonHasher, utils::QPGenRandom, PF, PHash};

    type Base = PsyCoordinatorPendingCheckpointBase<PF, PHash>;
    type Updates = PsyPreparedCoordinatorBlockStateUpdates<PF, PHash>;

    fn prepared_updates() -> Updates {
        PsyPreparedCoordinatorBlockStateUpdates {
            coordinator_id: 7,
            checkpoint_id: 11,
            unique_pending_id: 13,
            proc_checkpoint_unique_id: 17,
            old_base: Base::qp_rand_gen(),
            new_base: Base::qp_rand_gen(),
            update_global_contract_tree_nodes_ffs: vec![1, 2, 3],
            update_contract_function_tree_nodes_ffs: vec![4, 5],
            new_contract_leaves_ffs: vec![],
            new_contract_code_definitions: Vec::new(),
            update_user_registration_tree_nodes_ffs: vec![6],
            new_user_public_keys_ffs: vec![7, 8, 9, 10],
            new_public_key_hash_to_user_id_rows_ffs: vec![],
            update_global_user_tree_nodes_ffs: vec![11, 12],
            new_realm_guta_reward_tree_node_keys_ffs: vec![13],
            checkpoint_tree_update_proof: DeltaMerkleProofCore::qp_rand_gen(),
        }
    }

    fn direct_transition(updates: &Updates) -> CheckpointStateHashTransition<PHash> {
        CheckpointStateHashTransition {
            old_checkpoint_tree_root: updates.old_base.checkpoint_tree_root,
            new_checkpoint_tree_root: updates.new_base.checkpoint_tree_root,
            old_checkpoint_leaf_hash: updates.old_base.checkpoint_leaf_hash,
            new_checkpoint_leaf_hash: updates.new_base.checkpoint_leaf_hash,
        }
    }

    #[test]
    fn checkpoint_transition_hash_matches_direct_transition() {
        let updates = prepared_updates();
        let expected = direct_transition(&updates).get_hash::<PoseidonHasher>();
        assert_eq!(
            updates.get_checkpoint_state_transition_hash::<PoseidonHasher>(),
            expected
        );
    }

    #[test]
    fn public_inputs_hash_matches_manual_composition() {
        let updates = prepared_updates();
        let genesis = PHash::qp_rand_gen();
        let fingerprint = PHash::qp_rand_gen();

        let transition_hash = updates.get_checkpoint_state_transition_hash::<PoseidonHasher>();
        let expected = PoseidonHasher::two_to_one(
            &transition_hash,
            &PoseidonHasher::two_to_one(&genesis, &fingerprint),
        );
        assert_eq!(
            updates.get_checkpoint_transition_public_inputs_hash::<PoseidonHasher>(genesis, fingerprint),
            expected
        );
    }

    #[test]
    fn verifiable_state_transition_exposes_bases_and_config() {
        let updates = prepared_updates();
        let genesis = PHash::qp_rand_gen();
        let fingerprint = PHash::qp_rand_gen();

        let verifiable = updates.get_public_inputs_verifiable_state_transition(genesis, fingerprint);
        assert_eq!(verifiable.state_transition.checkpoint_transition, direct_transition(&updates));
        assert_eq!(verifiable.state_transition.genesis_checkpoint_state_transition_hash, genesis);
        assert_eq!(
            verifiable.state_transition.checkpoint_state_transition_circuit_fingerprint,
            fingerprint
        );
        assert_eq!(verifiable.checkpoint_leaf, updates.new_base.checkpoint_leaf);
        assert_eq!(
            verifiable.state_transition.get_public_inputs_hash_no_rewards_tag::<PoseidonHasher>(),
            updates.get_checkpoint_transition_public_inputs_hash::<PoseidonHasher>(genesis, fingerprint)
        );
    }
}
