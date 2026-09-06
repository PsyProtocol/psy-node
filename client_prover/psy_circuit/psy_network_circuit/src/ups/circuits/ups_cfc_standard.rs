use plonky2::{
    hash::hash_types::HashOut,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::{data::qhashout::QHashOut, job::traits::QProofStoreReaderSync};
use psy_client_data::ups::ups_cfc_standard_step::UPSCFCStandardTransactionCircuitInput;
use psy_common_circuit::{
    builder::pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates},
    circuits::traits::qstandard::{provable::QStandardCircuitProvable, QStandardCircuit, QStandardCircuitProvableWithProofStoreSync},
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    treeprover::qrecursion::standard::gadgets::attest_tree_aware_proof_in_tree::compute_tree_aware_proof_public_inputs,
};
use psy_config::network_constants::{UPS_CIRCUIT_WHITELIST_TREE_HEIGHT, UPS_SESSION_PROOF_TREE_HEIGHT};
use psy_crypto::hash::traits::hasher::MerkleZeroHasher;

use crate::ups::gadgets::{ups_cfc_standard::UPSVerifyCFCStandardStepGadget, verify_previous_ups_step::VerifyPreviousUPSStepProofInProofTreeGadget};

#[derive(Debug)]
pub struct UPSCFCStandardTransactionCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub verify_previous_ups_step_gadget: VerifyPreviousUPSStepProofInProofTreeGadget,
    pub standard_cfc_step_gadget: UPSVerifyCFCStandardStepGadget,

    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D> + 'static, const D: usize> UPSCFCStandardTransactionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new() -> Self {
        Self::new_with_config(UPS_SESSION_PROOF_TREE_HEIGHT as usize, UPS_CIRCUIT_WHITELIST_TREE_HEIGHT as usize)
    }
    pub fn new_with_config(ups_session_proof_tree_height: usize, ups_circuit_whitelist_tree_height: usize) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let verify_previous_ups_step_gadget = VerifyPreviousUPSStepProofInProofTreeGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            ups_session_proof_tree_height,
            ups_circuit_whitelist_tree_height,
        );

        let current_proof_tree_root = verify_previous_ups_step_gadget.current_proof_tree_root;

        let standard_cfc_step_gadget = UPSVerifyCFCStandardStepGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            &verify_previous_ups_step_gadget.previous_step_header_gadget,
            current_proof_tree_root,
            ups_session_proof_tree_height,
        );

        let inner_public_inputs_hash = standard_cfc_step_gadget.new_header_gadget.to_hash::<C::Hasher, C::F, D>(&mut builder);

        let public_inputs_hash =
            compute_tree_aware_proof_public_inputs::<C::Hasher, C::F, D>(&mut builder, current_proof_tree_root, inner_public_inputs_hash);

        builder.register_public_inputs(&public_inputs_hash.elements);

        builder.add_psy_type_b_common_gates();
        pad_circuit_degree::<C::F, D>(&mut builder, 11);

        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
        Self {
            verify_previous_ups_step_gadget,
            standard_cfc_step_gadget,
            circuit_data,
            fingerprint,
        }
    }

    fn prove_base_inner(&self, target: &UPSCFCStandardTransactionCircuitInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        /*
                println!("\n\n\nUPSCFCStandardTransactionCircuitInput:\n{:?}\n\n",&target);
                println!("\n\n\nUPSCFCStandardTransactionCircuitInput:\n{}\n\n",serde_json::to_string_pretty(&target).unwrap());
        */
        self.verify_previous_ups_step_gadget
            .set_witness(&mut pw, &target.verify_previous_ups_step)?;
        self.standard_cfc_step_gadget.set_witness(&mut pw, &target.standard_cfc_step)?;

        self.circuit_data.prove(pw)
    }
    pub fn prove_base(&self, target: &UPSCFCStandardTransactionCircuitInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_base_inner(target)
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D> for UPSCFCStandardTransactionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        self.fingerprint
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.circuit_data.verifier_only
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        &self.circuit_data.common
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuitProvable<UPSCFCStandardTransactionCircuitInput<C::F>, C, D>
    for UPSCFCStandardTransactionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_standard(&self, input: &UPSCFCStandardTransactionCircuitInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_base(input)
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvableWithProofStoreSync<S, UPSCFCStandardTransactionCircuitInput<C::F>, C, D> for UPSCFCStandardTransactionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_with_proof_store_sync(
        &self,
        _store: &S,
        input: &UPSCFCStandardTransactionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_standard(input)
    }
}
