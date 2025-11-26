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
