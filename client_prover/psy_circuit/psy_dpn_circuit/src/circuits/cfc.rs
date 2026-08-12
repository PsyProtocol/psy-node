use plonky2::{
    gates::gate::GateRef,
    hash::hash_types::HashOut,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::{data::qhashout::QHashOut, job::traits::QProofStoreReaderSync};
use psy_common_circuit::{
    builder::{
        hash::core::CircuitBuilderHashCore,
        pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates},
    },
    circuits::traits::qstandard::{provable::QStandardCircuitProvable, QStandardCircuit, QStandardCircuitProvableWithProofStoreSync},
    proof_minifier::pm_chain::PsyProofMinifierChain,
    u32::gates::comparison::ComparisonGate,
};
use psy_crypto::hash::traits::hasher::MerkleZeroHasher;
use psy_vm::{dpn::vm::def::DPNFunctionCircuitDefinition, vm::cfc_input::DapenContractFunctionCircuitInput};

use crate::vm::compile::PsyContractFunctionBuilderGadget;

#[derive(Debug)]
pub struct DapenContractFunctionCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub inputs: Vec<Target>,
    pub fn_builder_gadget: PsyContractFunctionBuilderGadget,

    // end circuit targets
    pub circuit_data: CircuitData<C::F, C, D>,
    // pub fingerprint: QHashOut<C::F>,
    pub minifier_chain: PsyProofMinifierChain<D, C::F, C>,

    // end circuit data
    pub fn_def: DPNFunctionCircuitDefinition,
}

impl<C: GenericConfig<D>, const D: usize> Clone for DapenContractFunctionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn clone(&self) -> Self {
        Self::new(
            &self.fn_def,
            self.fn_builder_gadget.state_reader.contract_state_tree_height,
            self.fn_builder_gadget.state_reader.session_proof_tree_height,
            self.fn_builder_gadget.state_reader.force_four_align,
        )
    }
}

impl<C: GenericConfig<D>, const D: usize> DapenContractFunctionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new(
        //coset_gate: &GateRef<C::F, D>,
        fn_def: &DPNFunctionCircuitDefinition,
        contract_state_tree_height: usize,
        session_proof_tree_height: usize,
        force_four_align: bool,
    ) -> Self {
        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let inputs = builder.add_virtual_targets(fn_def.circuit_inputs.len());
        let fn_builder_gadget = PsyContractFunctionBuilderGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            fn_def,
            contract_state_tree_height,
            session_proof_tree_height,
            inputs.clone(),
            force_four_align,
        );

        let inner_public_inputs_hash = fn_builder_gadget.tx_ctx_header.to_hash::<C::Hasher, C::F, D>(&mut builder);
        let public_inputs_hash = builder.hash_two_to_one::<C::Hasher>(fn_builder_gadget.session_proof_tree_root, inner_public_inputs_hash);

        builder.register_public_inputs(&public_inputs_hash.elements);
        //builder.add_psy_type_a_common_gates(Some(coset_gate.clone()));
        builder.add_psy_type_b_common_gates();
        pad_circuit_degree::<C::F, D>(&mut builder, 11);

        let circuit_data = builder.build::<C>();

        // let fingerprint =
        // QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        let added_gates_for_minifier = [GateRef::new(ComparisonGate::new(32, 16))];

        let minifier_chain =
            PsyProofMinifierChain::<D, C::F, C>::new_add_gates(&circuit_data.verifier_only, &circuit_data.common, 2, Some(&added_gates_for_minifier));

        Self {
            inputs,
            fn_builder_gadget,
            circuit_data,
            // fingerprint,
            fn_def: fn_def.clone(),
            minifier_chain,
        }
    }
    pub fn prove_base(&self, cfc_input: &DapenContractFunctionCircuitInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();

        pw.set_target_arr(&self.inputs, &cfc_input.inputs)?;

        pw.set_hash_target(self.fn_builder_gadget.session_proof_tree_root, cfc_input.session_proof_tree_root.0)?;

        self.fn_builder_gadget.tx_ctx_header.set_witness(&mut pw, &cfc_input.tx_input_ctx)?;
        self.fn_builder_gadget.state_reader.set_witness(&mut pw, cfc_input, &self.fn_def)?;

        let base_proof = self.circuit_data.prove(pw)?;
        let minified_proof = self.minifier_chain.prove(&base_proof)?;
        Ok(minified_proof)
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for DapenContractFunctionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        QHashOut(self.minifier_chain.get_fingerprint())
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        self.minifier_chain.get_verifier_data()
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        self.minifier_chain.get_common_data()
    }
}
impl<C: GenericConfig<D>, const D: usize> QStandardCircuitProvable<DapenContractFunctionCircuitInput<C::F>, C, D>
    for DapenContractFunctionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_standard(&self, input: &DapenContractFunctionCircuitInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_base(input)
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvableWithProofStoreSync<S, DapenContractFunctionCircuitInput<C::F>, C, D> for DapenContractFunctionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_with_proof_store_sync(
        &self,
        _store: &S,
        input: &DapenContractFunctionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_standard(input)
    }
}
