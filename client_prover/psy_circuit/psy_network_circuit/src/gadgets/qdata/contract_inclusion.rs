use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::qdata::{
    contract::PsyContractLeaf,
    contract_inclusion::{PsyContractFunctionInclusionProof, PsyContractInclusionProof},
};
use psy_common_circuit::{
    builder::core::CircuitBuilderHelpersCore,
    hash::merkle::gadgets::merkle_proof::MerkleProofGadget,
    traits::{CreatableTarget, CreatableWithHasherTarget, WitnessValueFor},
};
use psy_config::network_constants::{CONTRACT_FUNCTION_TREE_HEIGHT, GLOBAL_CONTRACT_TREE_HEIGHT};
use psy_crypto::hash::merkle::core::MerkleProofCore;

use super::contract::PsyContractLeafGadget;

#[derive(Clone, Debug)]
pub struct PsyContractInclusionProofGadget {
    pub contract_leaf: PsyContractLeafGadget,
    pub contract_tree_merkle_proof: MerkleProofGadget,

    // computed
    pub contract_leaf_hash: HashOutTarget,
}

impl PsyContractInclusionProofGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        // START: create targets that require witness
        let contract_leaf = PsyContractLeafGadget::create_virtual::<F, D>(builder);
        let contract_tree_merkle_proof = MerkleProofGadget::add_virtual_to::<H, F, D>(builder, GLOBAL_CONTRACT_TREE_HEIGHT as usize);
        // END: create targets that require witness

        // START: setup computed targets
        let contract_leaf_hash = contract_leaf.to_hash::<H, F, D>(builder);

        // ensure that the computed contract_leaf_hash matches our merkle proof value
        builder.connect_hashes(contract_leaf_hash, contract_tree_merkle_proof.value);

        // END: setup computed targets

        Self {
            contract_tree_merkle_proof,
            contract_leaf,
            contract_leaf_hash,
        }
    }
    pub fn set_witness_params<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        contract_leaf: &PsyContractLeaf<F>,
        contract_tree_merkle_proof: &MerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.contract_leaf.set_witness(witness, contract_leaf)?;
        self.contract_tree_merkle_proof
            .set_witness_core_proof_q_generic(witness, contract_tree_merkle_proof)
    }
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &PsyContractInclusionProof<F>) -> anyhow::Result<()> {
        self.set_witness_params(witness, &target.contract_leaf, &target.contract_tree_merkle_proof)
    }
}
impl CreatableWithHasherTarget for PsyContractInclusionProofGadget {
    fn create_virtual_with_hasher<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self::add_virtual_to::<H, F, D>(builder)
    }
}

impl<F: RichField> WitnessValueFor<PsyContractInclusionProofGadget, F, true> for PsyContractInclusionProof<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PsyContractInclusionProofGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<PsyContractInclusionProofGadget, F, false> for PsyContractInclusionProof<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PsyContractInclusionProofGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

#[derive(Clone, Debug)]
pub struct PsyContractFunctionInclusionProofGadget {
    pub contract_inclusion_proof: PsyContractInclusionProofGadget,
    pub contract_function_merkle_proof: MerkleProofGadget,

    // computed
    pub function_verifier_fingerprint: HashOutTarget,
    pub method_id: Target,
    // outputs_and_inputs = (num_outputs<<32)|num_inputs
    pub outputs_and_inputs: Target,

    pub num_inputs: Target,
    pub num_outputs: Target,
    /*
     */
}

impl PsyContractFunctionInclusionProofGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        // START: create targets that require witness
        let contract_inclusion_proof = PsyContractInclusionProofGadget::add_virtual_to::<H, F, D>(builder);

        let (contract_function_merkle_proof, cf_merkle_proof_index_bits) =
            MerkleProofGadget::add_virtual_to_get_index_bits::<H, F, D>(builder, CONTRACT_FUNCTION_TREE_HEIGHT as usize);
        // END: create targets that require witness

        // ensure that the index in the function tree is aligned to four leaves (two
        // least significant bits are 0) this is because each function takes up
        // four leaves (fingerprint, metadata, code hash, reserved)
        builder.assert_zero(cf_merkle_proof_index_bits[0].target);
        // builder.assert_zero(cf_merkle_proof_index_bits[1].target);

        // ensure the function_tree_root in the contract leaf matches our function tree
        // merkle proof's root
        builder.connect_hashes(
            contract_inclusion_proof.contract_leaf.function_tree_root,
            contract_function_merkle_proof.root,
        );

        // START: setup computed targets

        // each function has four leaves: fingerprint, metadata, code hash, reserved
        // zero

        let function_verifier_fingerprint = contract_function_merkle_proof.value;
        let method_id = contract_function_merkle_proof.siblings[0].elements[0];
        let outputs_and_inputs = contract_function_merkle_proof.siblings[0].elements[1];
        let (num_inputs, num_outputs) = builder.split_low_high_32bits(outputs_and_inputs);
        // END: setup computed targets

        Self {
            contract_inclusion_proof,
            contract_function_merkle_proof,
            function_verifier_fingerprint,
            method_id,
            outputs_and_inputs,
            num_inputs,
            num_outputs,
        }
    }
    pub fn set_witness_params<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        contract_inclusion_proof: &PsyContractInclusionProof<F>,
        contract_function_merkle_proof: &MerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.contract_inclusion_proof.set_witness(witness, contract_inclusion_proof)?;
        self.contract_function_merkle_proof
            .set_witness_core_proof_q_generic(witness, contract_function_merkle_proof)
    }
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &PsyContractFunctionInclusionProof<F>) -> anyhow::Result<()> {
        self.set_witness_params(witness, &target.contract_inclusion_proof, &target.contract_function_merkle_proof)
    }
}
impl CreatableWithHasherTarget for PsyContractFunctionInclusionProofGadget {
    fn create_virtual_with_hasher<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self::add_virtual_to::<H, F, D>(builder)
    }
}

impl<F: RichField> WitnessValueFor<PsyContractFunctionInclusionProofGadget, F, true> for PsyContractFunctionInclusionProof<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PsyContractFunctionInclusionProofGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<PsyContractFunctionInclusionProofGadget, F, false> for PsyContractFunctionInclusionProof<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PsyContractFunctionInclusionProofGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}
