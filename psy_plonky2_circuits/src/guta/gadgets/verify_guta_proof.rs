use parth_core::{crypto::hash::merkle_proof::MerkleProofCore, pgoldilocks::QHashOut};
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
use psy_data::guta::header::GlobalUserTreeAggregatorHeader;
use psy_plonky2_basic_helpers::builder::verify::CircuitBuilderVerifyProofHelpers;
use psy_plonky2_common_circuits::hash::merkle::gadgets::merkle_proof::MerkleProofGadget;

use super::{guta_header::GlobalUserTreeAggregatorHeaderGadget, helpers::ToGUTAHeader};

#[derive(Clone, Debug)]
pub struct VerifyGUTAProofGadget<const D: usize> {
    // start targets requiring witness
    pub guta_proof_header_gadget: GlobalUserTreeAggregatorHeaderGadget,
    pub guta_whitelist_merkle_proof: MerkleProofGadget,
    pub verifier_data: VerifierCircuitTarget,
    pub proof_target: ProofWithPublicInputsTarget<D>,
    // end targets requiring witness

}

impl<const D: usize> VerifyGUTAProofGadget<D> {
    pub fn add_virtual_to<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        builder: &mut CircuitBuilder<F, D>,
        proof_common_data: &CommonCircuitData<F, D>,
        verifier_data_cap_height: usize,
        guta_circuit_whitelist_tree_height: u8,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher:AlgebraicHasher<F>,
    {
        let verifier_data = builder.add_virtual_verifier_data(verifier_data_cap_height);
        let proof_target = builder.add_virtual_proof_with_pis(proof_common_data);

        builder.verify_proof::<C>(&proof_target, &verifier_data, proof_common_data);

        let proof_fingerprint = builder.get_circuit_fingerprint::<C::Hasher>(&verifier_data);


        let guta_whitelist_merkle_proof = MerkleProofGadget::add_virtual_to::<C::Hasher, F, D>(builder, guta_circuit_whitelist_tree_height as usize);


        let guta_proof_header_gadget = GlobalUserTreeAggregatorHeaderGadget::add_virtual_to::<F, D>(builder);

        // ensure that the header gadget and merkle proof have the same whitelist root
        builder.connect_hashes(
            guta_proof_header_gadget.guta_circuit_whitelist,
            guta_whitelist_merkle_proof.root
        );


        // start: check child proof public inputs
        let expected_proof_public_inputs_hash = guta_proof_header_gadget.to_hash::<C::Hasher, C::F, D>(builder);


        assert_eq!(
            proof_target.public_inputs.len(),
            15,
            "GUTA proofs should have 15 public inputs"
        );
        let proof_public_input_hash = HashOutTarget {
            elements: [
                proof_target.public_inputs[11],
                proof_target.public_inputs[12],
                proof_target.public_inputs[13],
                proof_target.public_inputs[14],
            ],
        };

        tracing::debug!("🎯 GUTA gadget - guta_proof_header_gadget: {:?}", guta_proof_header_gadget);
        tracing::debug!("🎯 GUTA gadget - expected_proof_public_inputs_hash targets: {:?}", expected_proof_public_inputs_hash.elements);
        tracing::debug!("🎯 GUTA gadget - proof_public_input_hash targets: {:?}", proof_public_input_hash.elements);

        // ensure the whitelist root and state transition is correct for the proof
        builder.connect_hashes(expected_proof_public_inputs_hash, proof_public_input_hash);
        // end: check child proof public inputs

        // ensure the leaf revealed in the whitelist merkle proof is actually the fingerprint of the proof
        builder.connect_hashes(guta_whitelist_merkle_proof.value, proof_fingerprint);
        Self {
            guta_proof_header_gadget,
            guta_whitelist_merkle_proof,
            verifier_data,
            proof_target,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        &self,
        witness: &mut impl Witness<F>,
        guta_whitelist_merkle_proof: &MerkleProofCore<QHashOut<F>>,
        guta_proof_header: &GlobalUserTreeAggregatorHeader<F, QHashOut<F>>,
        proof: &ProofWithPublicInputs<F, C, D>,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<()> where
    <C as GenericConfig<D>>::Hasher:AlgebraicHasher<F>, {
        tracing::debug!("🎯 Verify GUTA Proof set_witness - guta_proof_header: {}, public_inputs: {}",
            serde_json::to_string_pretty(guta_proof_header).unwrap(),
            serde_json::to_string_pretty(&proof.public_inputs).unwrap());
        self.guta_whitelist_merkle_proof.set_witness_generic(
            witness,
            F::from_noncanonical_u64(guta_whitelist_merkle_proof.index),
            guta_whitelist_merkle_proof.value,
            &guta_whitelist_merkle_proof.siblings,
        )?;
        self.guta_proof_header_gadget.set_witness(witness, guta_proof_header)?;

        witness.set_proof_with_pis_target(&self.proof_target, &proof)?;
        witness.set_verifier_data_target(&self.verifier_data, &verifier_data)
    }


    pub fn set_witness_ho<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        &self,
        witness: &mut impl Witness<F>,
        guta_whitelist_merkle_proof: &MerkleProofCore<QHashOut<F>>,
        guta_proof_header: &GlobalUserTreeAggregatorHeader<F, HashOut<F>>,
        proof: &ProofWithPublicInputs<F, C, D>,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<()> where
    <C as GenericConfig<D>>::Hasher:AlgebraicHasher<F>, {
        tracing::debug!("🎯 Verify GUTA Proof set_witness - guta_proof_header: {}, public_inputs: {}",
            serde_json::to_string_pretty(guta_proof_header).unwrap(),
            serde_json::to_string_pretty(&proof.public_inputs).unwrap());
        self.guta_whitelist_merkle_proof.set_witness_generic(
            witness,
            F::from_noncanonical_u64(guta_whitelist_merkle_proof.index),
            guta_whitelist_merkle_proof.value,
            &guta_whitelist_merkle_proof.siblings,
        )?;
        self.guta_proof_header_gadget.set_witness_ho(witness, guta_proof_header)?;

        witness.set_proof_with_pis_target(&self.proof_target, &proof)?;
        witness.set_verifier_data_target(&self.verifier_data, &verifier_data)
    }
}

impl<const D: usize> ToGUTAHeader<D> for VerifyGUTAProofGadget<D> {
    fn get_guta_header<H: AlgebraicHasher<F>, F: RichField + Extendable<D>>(&self, _builder: &mut CircuitBuilder<F, D>, _: HashOutTarget) -> GlobalUserTreeAggregatorHeaderGadget {
        self.guta_proof_header_gadget.to_owned()
    }
}
