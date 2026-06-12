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
use psy_crypto::hash::{merkle::core::DeltaMerkleProofCore, traits::hasher::MerkleZeroHasher};

use crate::{
    builder::{hash::core::CircuitBuilderHashCore, verify::CircuitBuilderVerifyProofHelpers},
    hash::merkle::gadgets::delta_merkle_proof::DeltaMerkleProofGadget,
};

#[derive(Clone, Debug)]
pub struct VerifyLeafProofGadget<const D: usize> {
    // start targets requiring witness
    pub insert_leaf_proof: DeltaMerkleProofGadget,
    pub verifier_data: VerifierCircuitTarget,
    pub proof_target: ProofWithPublicInputsTarget<D>,
    // end targets requiring witness

    // start computed targets
    pub proof_fingerprint: HashOutTarget,
    pub proof_public_input_hash: HashOutTarget,
    pub proof_leaf_combo_hash: HashOutTarget,
    // end computed targets
}

impl<const D: usize> VerifyLeafProofGadget<D> {
    pub fn add_virtual_to<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        builder: &mut CircuitBuilder<F, D>,
        q_recursion_tree_height: usize,
        proof_common_data: &CommonCircuitData<F, D>,
        verifier_data_cap_height: usize,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: MerkleZeroHasher<HashOut<F>> + AlgebraicHasher<F>,
    {
        let verifier_data = builder.add_virtual_verifier_data(verifier_data_cap_height);
        let proof_target = builder.add_virtual_proof_with_pis(proof_common_data);

        builder.verify_proof::<C>(&proof_target, &verifier_data, proof_common_data);

        let proof_fingerprint = builder.get_circuit_fingerprint::<C::Hasher>(&verifier_data);

        assert_eq!(proof_target.public_inputs.len(), 4, "leaf proofs should have 4 public inputs");

        let proof_public_input_hash = HashOutTarget {
            elements: [
                proof_target.public_inputs[0],
                proof_target.public_inputs[1],
                proof_target.public_inputs[2],
                proof_target.public_inputs[3],
            ],
        };

        // leaf value should be hash(proof_fingerprint, proof_public_input_hash)

        let expected_leaf_value = builder.hash_two_to_one::<C::Hasher>(proof_fingerprint, proof_public_input_hash);

        let insert_leaf_proof = DeltaMerkleProofGadget::add_virtual_to_append_only::<C::Hasher, F, D>(builder, q_recursion_tree_height);

        builder.connect_hashes(expected_leaf_value, insert_leaf_proof.new_value);

        let proof_leaf_combo_hash = expected_leaf_value;

        let zero_hash = builder.constant_hash(HashOut::ZERO);
        builder.connect_hashes(insert_leaf_proof.old_value, zero_hash);

        Self {
            insert_leaf_proof,
            verifier_data,
            proof_target,
            proof_fingerprint,
            proof_public_input_hash,
            proof_leaf_combo_hash,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        &self,
        witness: &mut impl Witness<F>,
        insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<F>>,
        proof: &ProofWithPublicInputs<F, C, D>,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<()>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.insert_leaf_proof.set_witness(
            witness,
            F::from_noncanonical_u64(insert_leaf_proof.index),
            insert_leaf_proof.old_value,
            insert_leaf_proof.new_value,
            &insert_leaf_proof.siblings,
        )?;
        witness.set_proof_with_pis_target(&self.proof_target, &proof)?;
        witness.set_verifier_data_target(&self.verifier_data, &verifier_data)
    }
}
