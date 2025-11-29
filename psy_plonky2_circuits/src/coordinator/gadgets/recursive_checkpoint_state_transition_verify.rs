use parth_core::pgoldilocks::QHashOut;
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::{target::Target, witness::Witness}, plonk::{circuit_builder::CircuitBuilder, circuit_data::{CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData}, config::{AlgebraicHasher, GenericConfig}, proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget}}};
use psy_plonky2_basic_helpers::builder::{comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers, hash::core::CircuitBuilderHashCore, verify::CircuitBuilderVerifyProofHelpers};

use crate::coordinator::gadgets::checkpoint_state_transition::{CheckpointStateHashTransitionGadget, CheckpointStateTransitionPublicInputsGadget};


// we keep this separate from DPNProvingSessionCompactMethodCallGadget incase it
// changes in the future
#[derive(Debug, Clone)]
pub struct VerifyRecursiveCheckpointStateTransitionProofGadget<const D: usize> {
    pub previous_checkpoint_state_transition_verifier_data: VerifierCircuitTarget,
    pub previous_checkpoint_state_transition_proof_target: ProofWithPublicInputsTarget<D>,
    pub last_old_checkpoint_tree_leaf_hash: HashOutTarget,
    pub last_old_checkpoint_tree_root_hash: HashOutTarget,
}

impl<const D: usize> VerifyRecursiveCheckpointStateTransitionProofGadget<D> {
    pub fn add_virtual_to<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        builder: &mut CircuitBuilder<F, D>,
        checkpoint_transition_proof_common_data: &CommonCircuitData<F, D>,
        checkpoint_transition_proof_common_data_verifier_data_cap_height: usize,
        known_checkpoint_state_transition_genesis_fingerprint: QHashOut<C::F>,
        current_public_inputs_gadget: CheckpointStateTransitionPublicInputsGadget,
        checkpoint_id: Target,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let is_previous_proof_genensis_block = builder.is_equal_to_u64(checkpoint_id, 1);
        let genesis_checkpoint_transition_proof_fingerprint = builder.constant_qhash(known_checkpoint_state_transition_genesis_fingerprint);

        let previous_checkpoint_state_transition_verifier_data = builder.add_virtual_verifier_data(checkpoint_transition_proof_common_data_verifier_data_cap_height);
        let previous_checkpoint_state_transition_proof_target = builder.add_virtual_proof_with_pis(checkpoint_transition_proof_common_data);

        builder.verify_proof::<C>(&previous_checkpoint_state_transition_proof_target, &previous_checkpoint_state_transition_verifier_data, checkpoint_transition_proof_common_data);

        let last_old_checkpoint_tree_leaf_hash = builder.add_virtual_hash();
        let last_old_checkpoint_tree_root_hash = builder.add_virtual_hash();

        let previous_checkpoint_state_transition = CheckpointStateHashTransitionGadget {
            old_checkpoint_leaf_hash: last_old_checkpoint_tree_leaf_hash,
            old_checkpoint_tree_root: last_old_checkpoint_tree_root_hash,
            new_checkpoint_leaf_hash: current_public_inputs_gadget.checkpoint_transition.old_checkpoint_leaf_hash,
            new_checkpoint_tree_root: current_public_inputs_gadget.checkpoint_transition.old_checkpoint_tree_root,
        };
        let previous_checkpoint_state_transition_hash = previous_checkpoint_state_transition.get_hash::<C::Hasher, F ,D>(builder);



        // if is previous proof is genesis block, use known genesis state transition hash
        builder.connect_hashes_if_true(is_previous_proof_genensis_block, previous_checkpoint_state_transition_hash, current_public_inputs_gadget.genesis_checkpoint_state_transition_hash);
        
        let previous_proof_fingerprint = builder.get_circuit_fingerprint::<C::Hasher>(&previous_checkpoint_state_transition_verifier_data);
        // if is previous proof is genesis block, use known genesis fingerprint
        // otherwise, use standard state transition fingerprint
        builder.connect_hashes_switch(is_previous_proof_genensis_block, previous_proof_fingerprint, genesis_checkpoint_transition_proof_fingerprint, current_public_inputs_gadget.checkpoint_state_transition_circuit_fingerprint);


        assert_eq!(previous_checkpoint_state_transition_proof_target.public_inputs.len(), 4, "state transition proofs must have 4 public inputs");

        let actual_previous_proof_public_inputs_hash = HashOutTarget {
            elements: [
                previous_checkpoint_state_transition_proof_target.public_inputs[0],
                previous_checkpoint_state_transition_proof_target.public_inputs[1],
                previous_checkpoint_state_transition_proof_target.public_inputs[2],
                previous_checkpoint_state_transition_proof_target.public_inputs[3]
            ]
        };

        let expected_previous_proof_public_inputs_gadget = CheckpointStateTransitionPublicInputsGadget {
            checkpoint_transition: previous_checkpoint_state_transition,
            genesis_checkpoint_state_transition_hash: current_public_inputs_gadget.genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint: current_public_inputs_gadget.checkpoint_state_transition_circuit_fingerprint,
        }.get_public_inputs_hash_no_rewards_tag::<C::Hasher, F, D>(builder);



        // ensure the previous proof's public inputs hash matches the expected value
        builder.connect_hashes(actual_previous_proof_public_inputs_hash, expected_previous_proof_public_inputs_gadget);

        Self {
            previous_checkpoint_state_transition_verifier_data,
            previous_checkpoint_state_transition_proof_target,
            last_old_checkpoint_tree_leaf_hash,
            last_old_checkpoint_tree_root_hash,
        }
    }
    pub fn set_witness_params<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        &self,
        witness: &mut impl Witness<F>,
        last_old_checkpoint_tree_leaf_hash: QHashOut<F>,
        last_old_checkpoint_tree_root_hash: QHashOut<F>,
        previous_checkpoint_state_transition_proof: &ProofWithPublicInputs<F, C, D>,
        previous_checkpoint_state_transition_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<()>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        witness.set_hash_target(self.last_old_checkpoint_tree_leaf_hash, last_old_checkpoint_tree_leaf_hash.0)?;
        witness.set_hash_target(self.last_old_checkpoint_tree_root_hash, last_old_checkpoint_tree_root_hash.0)?;
        witness.set_verifier_data_target::<C, D>(&self.previous_checkpoint_state_transition_verifier_data, previous_checkpoint_state_transition_verifier_data)?;
        witness.set_proof_with_pis_target::<C, D>(&self.previous_checkpoint_state_transition_proof_target, previous_checkpoint_state_transition_proof)?;
        
        Ok(())
    }
}
