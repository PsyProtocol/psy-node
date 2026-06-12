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
use psy_crypto::{
    common::witnesses::qrecursion::header::QRecursionAggStandardHeader,
    hash::{merkle::core::MerkleProofCore, traits::hasher::MerkleZeroHasher},
};

use super::agg_proof_header::QRecursionAggStandardHeaderGadget;
use crate::{
    builder::verify::CircuitBuilderVerifyProofHelpers, hash::merkle::gadgets::merkle_proof::MerkleProofGadget,
    treeprover::qrecursion::standard::config::QRECURSION_CIRCUIT_WHITELIST_HEIGHT,
};

#[derive(Clone, Debug)]
pub struct VerifyAggProofGadget<const D: usize> {
    // start targets requiring witness
    pub agg_proof_header_gadget: QRecursionAggStandardHeaderGadget,
    pub agg_whitelist_merkle_proof: MerkleProofGadget,
    pub verifier_data: VerifierCircuitTarget,
    pub proof_target: ProofWithPublicInputsTarget<D>,
    // end targets requiring witness
}

impl<const D: usize> VerifyAggProofGadget<D> {
    pub fn add_virtual_to<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        builder: &mut CircuitBuilder<F, D>,
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

        let agg_whitelist_merkle_proof = MerkleProofGadget::add_virtual_to::<C::Hasher, F, D>(builder, QRECURSION_CIRCUIT_WHITELIST_HEIGHT);

        let agg_proof_header_gadget = QRecursionAggStandardHeaderGadget::add_virtual_to::<F, D>(builder);

        // ensure that the header gadget and merkle proof have the same whitelist root
        builder.connect_hashes(agg_proof_header_gadget.agg_circuit_whitelist_root, agg_whitelist_merkle_proof.root);

        // start: check child proof public inputs
        let expected_proof_public_inputs_hash = agg_proof_header_gadget.get_combined_hash::<C::Hasher, C::F, D>(builder);

        assert_eq!(proof_target.public_inputs.len(), 4, "children proofs should have 4 public inputs");
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
        // end: check child proof public inputs

        // ensure the leaf revealed in the whitelist merkle proof is actually the
        // fingerprint of the proof
        builder.connect_hashes(agg_whitelist_merkle_proof.value, proof_fingerprint);
        Self {
            agg_proof_header_gadget,
            agg_whitelist_merkle_proof,
            verifier_data,
            proof_target,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        &self,
        witness: &mut impl Witness<F>,
        agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<F>>,
        agg_proof_header: &QRecursionAggStandardHeader<F>,
        proof: &ProofWithPublicInputs<F, C, D>,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<()>
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.agg_whitelist_merkle_proof.set_witness_generic(
            witness,
            F::from_noncanonical_u64(agg_whitelist_merkle_proof.index),
            agg_whitelist_merkle_proof.value,
            &agg_whitelist_merkle_proof.siblings,
        )?;
        self.agg_proof_header_gadget.set_witness(witness, agg_proof_header)?;

        witness.set_proof_with_pis_target(&self.proof_target, &proof)?;
        witness.set_verifier_data_target(&self.verifier_data, &verifier_data)
    }
}
