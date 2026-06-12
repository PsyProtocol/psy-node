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
use psy_client_data::ups::start_step_register_user::UPSStartStepRegisterUserInput;
use psy_common_circuit::{
    builder::{
        hash::core::CircuitBuilderHashCore,
        pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates},
    },
    circuits::traits::qstandard::{provable::QStandardCircuitProvable, QStandardCircuit, QStandardCircuitProvableWithProofStoreSync},
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    traits::CreatableWithHasherTarget,
    treeprover::qrecursion::standard::gadgets::attest_tree_aware_proof_in_tree::compute_tree_aware_proof_public_inputs,
};
use psy_config::network_constants::UPS_SESSION_PROOF_TREE_HEIGHT;
use psy_crypto::hash::traits::hasher::MerkleZeroHasher;

use crate::ups::gadgets::ups_start_register_user::UPSStartStepRegisterUserGadget;

#[derive(Debug)]
pub struct UPSStartSessionRegisterUserCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub start_step_gadget: UPSStartStepRegisterUserGadget,

    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D> + 'static, const D: usize> UPSStartSessionRegisterUserCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new_with_config(
        //coset_gate: &GateRef<C::F, D>,
        empty_ups_proof_tree_root: QHashOut<C::F>,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let start_step_gadget = UPSStartStepRegisterUserGadget::create_virtual_with_hasher::<C::Hasher, C::F, D>(&mut builder);

        let empty_ups_proof_tree_root_target = builder.constant_qhash(empty_ups_proof_tree_root);

        let inner_public_inputs_hash = start_step_gadget.header_gadget.to_hash::<C::Hasher, C::F, D>(&mut builder);

        let public_inputs_hash =
            compute_tree_aware_proof_public_inputs::<C::Hasher, C::F, D>(&mut builder, empty_ups_proof_tree_root_target, inner_public_inputs_hash);

        builder.register_public_inputs(&public_inputs_hash.elements);

        builder.add_psy_type_b_common_gates();
        pad_circuit_degree::<C::F, D>(&mut builder, 11);
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
        Self {
            start_step_gadget,
            circuit_data,
            fingerprint,
        }
    }

    fn prove_base_inner(&self, target: &UPSStartStepRegisterUserInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();

        self.start_step_gadget.set_witness(&mut pw, target)?;

        self.circuit_data.prove(pw)
    }
    pub fn prove_base(&self, target: &UPSStartStepRegisterUserInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_base_inner(target)
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> UPSStartSessionRegisterUserCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new() -> Self {
        let empty_tree_zero_hash = C::Hasher::get_zero_hash(UPS_SESSION_PROOF_TREE_HEIGHT as usize);
        Self::new_with_config(QHashOut(empty_tree_zero_hash))
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D> for UPSStartSessionRegisterUserCircuit<C, D>
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

impl<C: GenericConfig<D>, const D: usize> QStandardCircuitProvable<UPSStartStepRegisterUserInput<C::F>, C, D>
    for UPSStartSessionRegisterUserCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_standard(&self, input: &UPSStartStepRegisterUserInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_base(input)
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvableWithProofStoreSync<S, UPSStartStepRegisterUserInput<C::F>, C, D> for UPSStartSessionRegisterUserCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_with_proof_store_sync(
        &self,
        _store: &S,
        input: &UPSStartStepRegisterUserInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_standard(input)
    }
}
