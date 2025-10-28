use parth_core::{crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher}, pgoldilocks::QHashOut};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_data::guta::header::GlobalUserTreeAggregatorHeader;
use super::{guta_header::GlobalUserTreeAggregatorHeaderGadget, guta_line::GUTAHeaderLineProofGadget, helpers::ToGUTAHeader, verify_guta_proof::VerifyGUTAProofGadget};

#[derive(Clone, Debug)]
pub struct VerifyGUTAProofToLineGadget<const D: usize> {
    // start targets requiring witness
    pub verify_guta_proof_gadget: VerifyGUTAProofGadget<D>,
    pub header_line_gadget: GUTAHeaderLineProofGadget,
    // end targets requiring witness

}

impl<const D: usize> VerifyGUTAProofToLineGadget<D> {
    pub fn add_virtual_to<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        builder: &mut CircuitBuilder<F, D>,
        proof_common_data: &CommonCircuitData<F, D>,
        verifier_data_cap_height: usize,
        global_user_tree_realm_height: usize,
        global_user_tree_height: usize,
        guta_circuit_whitelist_tree_height: u8,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: MerkleZeroHasher<HashOut<F>> +AlgebraicHasher<F>,
    {

        let verify_guta_proof_gadget = VerifyGUTAProofGadget::<D>::add_virtual_to::<C,F>(
            builder,
            proof_common_data,
            verifier_data_cap_height,
            guta_circuit_whitelist_tree_height,
        );
        let header_line_gadget = GUTAHeaderLineProofGadget::add_virtual_to::<C::Hasher,F,D>(
            builder,
            global_user_tree_realm_height,
            global_user_tree_height,
            &verify_guta_proof_gadget.guta_proof_header_gadget
        );

        tracing::debug!("📊 header_line_gadget.new_guta_header: {:?}", header_line_gadget.new_guta_header);
        Self {
            verify_guta_proof_gadget,
            header_line_gadget,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        &self,
        witness: &mut impl Witness<F>,
        guta_whitelist_merkle_proof: &MerkleProofCore<QHashOut<F>>,
        guta_proof_header: &GlobalUserTreeAggregatorHeader<F, QHashOut<F>>,
        proof: &ProofWithPublicInputs<F, C, D>,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
        top_line_siblings: &[QHashOut<F>],
    ) -> anyhow::Result<()> where
    <C as GenericConfig<D>>::Hasher:AlgebraicHasher<F>, {
        self.verify_guta_proof_gadget.set_witness(
            witness,
            guta_whitelist_merkle_proof,
            guta_proof_header,
            proof,
            verifier_data
        )?;
        self.header_line_gadget.set_witness_params(
            witness,
            top_line_siblings
        )
    }
    pub fn get_guta_header_line(&self) -> GlobalUserTreeAggregatorHeaderGadget {
        self.header_line_gadget.new_guta_header
    }
}

impl<const D: usize> ToGUTAHeader<D> for VerifyGUTAProofToLineGadget<D> {
    fn get_guta_header<H: AlgebraicHasher<F>, F: RichField + Extendable<D>>(&self, _builder: &mut CircuitBuilder<F, D>, _: HashOutTarget) -> GlobalUserTreeAggregatorHeaderGadget {
        self.get_guta_header_line()
    }
}
