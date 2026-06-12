use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::hash::{merkle::core::MerkleProofCore, traits::hasher::MerkleZeroHasher};

use crate::{
    builder::{hash::core::CircuitBuilderHashCore, verify::CircuitBuilderVerifyProofHelpers},
    hash::merkle::gadgets::merkle_proof::MerkleProofGadget, treeprover::qrecursion::standard::config::QRECURSION_CIRCUIT_WHITELIST_HEIGHT,
};

#[derive(Clone, Debug)]
pub struct VerifyAggProofGadget<const D: usize> {
    // start targets requiring witness
    pub start_proof_tree_root: HashOutTarget,
    pub end_proof_tree_root: HashOutTarget,
    pub agg_whitelist_merkle_proof: MerkleProofGadget,
    pub verifier_data: VerifierCircuitTarget,
    pub proof_target: ProofWithPublicInputsTarget<D>,
    // end targets requiring witness

    // start computed targets
    pub agg_whitelist_merkle_root: HashOutTarget,
    // end computed targets
}

impl<const D: usize> VerifyAggProofGadget<D> {
    pub fn add_virtual_to<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        builder: &mut CircuitBuilder<F, D>,
        proof_common_data: &CommonCircuitData<F, D>,
        verifier_data_cap_height: usize,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: MerkleZeroHasher<HashOut<F>> +AlgebraicHasher<F>,
    {
        let verifier_data = builder.add_virtual_verifier_data(verifier_data_cap_height);
        let proof_target = builder.add_virtual_proof_with_pis(proof_common_data);

        builder.verify_proof::<C>(&proof_target, &verifier_data, proof_common_data);

        let proof_fingerprint = builder.get_circuit_fingerprint::<C::Hasher>(&verifier_data);


        let agg_whitelist_merkle_proof = MerkleProofGadget::add_virtual_to::<C::Hasher, F, D>(builder, QRECURSION_CIRCUIT_WHITELIST_HEIGHT);

        let start_proof_tree_root = builder.add_virtual_hash();
        let end_proof_tree_root = builder.add_virtual_hash();
        let agg_whitelist_merkle_root = agg_whitelist_merkle_proof.root;

        let state_transition_combo = builder.hash_two_to_one::<C::Hasher>(start_proof_tree_root, end_proof_tree_root);
        let expected_proof_public_inputs_hash = builder.hash_two_to_one::<C::Hasher>(state_transition_combo, agg_whitelist_merkle_root);


        assert_eq!(
            proof_target.public_inputs.len(),
            4,
            "children proofs should have 4 public inputs"
        );
        let proof_public_input_hash = HashOutTarget {
            elements: [
                proof_target.public_inputs[0],
                proof_target.public_inputs[1],
                proof_target.public_inputs[2],
                proof_target.public_inputs[3],
            ],
        };

        // ensure the whitelist root and state transition is correct for the proof
        builder.connect_hashes(expected_proof_public_inputs_hash, proof_public_input_hash);

        // ensure the leaf revealed in the whitelist merkle proof is actually the fingerprint of the proof
        builder.connect_hashes(agg_whitelist_merkle_proof.value, proof_fingerprint);
        Self {
            start_proof_tree_root,
            end_proof_tree_root,
            agg_whitelist_merkle_proof,
            verifier_data,
            proof_target,
            agg_whitelist_merkle_root,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        &self,
        witness: &mut impl Witness<F>,
        start_proof_tree_root: QHashOut<F>,
        end_proof_tree_root: QHashOut<F>,
        agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<F>>,
        proof: &ProofWithPublicInputs<F, C, D>,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) where
    <C as GenericConfig<D>>::Hasher:AlgebraicHasher<F>, {
        witness.set_hash_target(self.start_proof_tree_root, start_proof_tree_root.0);
        witness.set_hash_target(self.end_proof_tree_root, end_proof_tree_root.0);
        self.agg_whitelist_merkle_proof.set_witness_generic(
            witness,
            F::from_noncanonical_u64(agg_whitelist_merkle_proof.index),
            agg_whitelist_merkle_proof.value,
            &agg_whitelist_merkle_proof.siblings,
        );
        witness.set_proof_with_pis_target(&self.proof_target, &proof);
        witness.set_verifier_data_target(&self.verifier_data, &verifier_data);
    }
}
