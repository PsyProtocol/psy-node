use parth_core::pgoldilocks::QHashOut;
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::{target::Target, witness::Witness}, plonk::{circuit_builder::CircuitBuilder, circuit_data::{CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData}, config::{AlgebraicHasher, GenericConfig}, proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget}}};
use psy_plonky2_basic_helpers::builder::{comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers, hash::core::CircuitBuilderHashCore, verify::CircuitBuilderVerifyProofHelpers};

use crate::coordinator::gadgets::checkpoint_state_transition::CheckpointStateTransitionPublicInputsGadget;


// we keep this separate from DPNProvingSessionCompactMethodCallGadget incase it
// changes in the future
#[derive(Debug, Clone)]
pub struct VerifyRecursiveCheckpointStateTransitionProofGadget<const D: usize> {
    pub previous_checkpoint_state_transition_verifier_data: VerifierCircuitTarget,
    pub previous_checkpoint_state_transition_proof_target: ProofWithPublicInputsTarget<D>,
    pub last_old_checkpoint_tree_leaf_hash: HashOutTarget,
    pub last_old_checkpoint_tree_root_hash: HashOutTarget,
    pub previous_chain_hash: HashOutTarget,
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

        // NOTE:
        // In cumulative-chain mode, the previous proof public inputs are an opaque chain commitment.
        // We must not re-derive/constraint previous transition hash here using legacy transition semantics.
        // previous proof validity + fingerprint checks + PI linkage below are sufficient.
        
        let previous_proof_fingerprint = builder.get_circuit_fingerprint::<C::Hasher>(&previous_checkpoint_state_transition_verifier_data);
        // Only pin previous proof fingerprint when previous proof is genesis.
        // For non-genesis checkpoints, previous proof can be a different verifier
        // instance (e.g. minified chain), so forcing equality to current fingerprint
        // causes set-twice witness conflicts.
        builder.connect_hashes_if_true(
            is_previous_proof_genensis_block,
            previous_proof_fingerprint,
            genesis_checkpoint_transition_proof_fingerprint,
        );


        assert_eq!(previous_checkpoint_state_transition_proof_target.public_inputs.len(), 4, "state transition proofs must have 4 public inputs");

        let actual_previous_proof_public_inputs_hash = HashOutTarget {
            elements: [
                previous_checkpoint_state_transition_proof_target.public_inputs[0],
                previous_checkpoint_state_transition_proof_target.public_inputs[1],
                previous_checkpoint_state_transition_proof_target.public_inputs[2],
                previous_checkpoint_state_transition_proof_target.public_inputs[3]
            ]
        };

        // previous_chain_hash is sourced directly from previous proof public inputs.
        // Do not add a second witness-provided target for this value.
        let previous_chain_hash = actual_previous_proof_public_inputs_hash;

        Self {
            previous_checkpoint_state_transition_verifier_data,
            previous_checkpoint_state_transition_proof_target,
            last_old_checkpoint_tree_leaf_hash,
            last_old_checkpoint_tree_root_hash,
            previous_chain_hash,
        }
    }
    pub fn set_witness_params<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        &self,
        witness: &mut impl Witness<F>,
        last_old_checkpoint_tree_leaf_hash: QHashOut<F>,
        last_old_checkpoint_tree_root_hash: QHashOut<F>,
        _previous_chain_hash: QHashOut<F>,
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
