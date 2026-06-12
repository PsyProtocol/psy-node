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
use psy_crypto::hash::traits::hasher::MerkleZeroHasher;

#[derive(Clone, Debug)]
pub struct VerifyAggRootGadget<const D: usize> {
    // start targets requiring witness
    pub verifier_data: VerifierCircuitTarget,
    pub proof_target: ProofWithPublicInputsTarget<D>,

    pub proof_tree_root_hash: HashOutTarget,
    // end targets requiring witness
}

impl<const D: usize> VerifyAggRootGadget<D> {
    pub fn add_virtual_to<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        builder: &mut CircuitBuilder<F, D>,
        proof_common_data: &CommonCircuitData<F, D>,
        //verifier_data_cap_height: usize,
        knonw_root_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: MerkleZeroHasher<HashOut<F>> + AlgebraicHasher<F>,
    {
        //let verifier_data =
        // builder.add_virtual_verifier_data(verifier_data_cap_height);
        let verifier_data = builder.constant_verifier_data(knonw_root_verifier_data);

        let proof_target = builder.add_virtual_proof_with_pis(proof_common_data);

        builder.verify_proof::<C>(&proof_target, &verifier_data, proof_common_data);

        assert_eq!(proof_target.public_inputs.len(), 4, "children proofs should have 4 public inputs");
        let proof_public_input_hash = HashOutTarget {
            elements: [
                proof_target.public_inputs[0],
                proof_target.public_inputs[1],
                proof_target.public_inputs[2],
                proof_target.public_inputs[3],
            ],
        };
        Self {
            verifier_data,
            proof_target,
            proof_tree_root_hash: proof_public_input_hash,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        &self,
        witness: &mut impl Witness<F>,
        proof: &ProofWithPublicInputs<F, C, D>,
        //verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<()>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        witness.set_proof_with_pis_target(&self.proof_target, &proof)
        //witness.set_verifier_data_target(&self.verifier_data,
        // &verifier_data);
    }
}
