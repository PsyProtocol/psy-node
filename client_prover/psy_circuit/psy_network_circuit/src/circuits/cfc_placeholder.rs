use plonky2::{
    field::types::PrimeField64,
    hash::hash_types::HashOut,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::data::qhashout::QHashOut;
use psy_common_circuit::{
    builder::hash::core::CircuitBuilderHashCore,
    circuits::traits::qstandard::QStandardCircuit,
    hash::merkle::gadgets::delta_merkle_proof::DeltaMerkleProofGadget,
    proof_minifier::{pm_chain_dynamic::PsyProofMinifierDynamicChain, pm_core::get_circuit_fingerprint_generic},
};
use psy_crypto::hash::{
    merkle::{core::DeltaMerkleProofCore, utils::simple_merkle_tree::SimpleMerkleTree},
    traits::hasher::MerkleZeroHasherWithMarkedLeaf,
};

#[derive(Debug)]
pub struct CFCPlaceholderCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub delta_merkle_proofs: Vec<DeltaMerkleProofGadget>,

    // end circuit targets
    pub base_circuit_data: CircuitData<C::F, C, D>,
    pub base_fingerprint: QHashOut<C::F>,
    pub minifier_chain: Option<PsyProofMinifierDynamicChain<D, C::F, C>>,
    pub enable_minifier: bool,
    // end circuit data
}

impl<C: GenericConfig<D> + 'static, const D: usize> CFCPlaceholderCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new_with_minifier() -> Self {
        Self::new_with_config(30, 128, true)
    }
    pub fn new_without_minifier() -> Self {
        Self::new_with_config(30, 128, true)
    }
    pub fn new_with_config(
        //coset_gate: &GateRef<C::F, D>,
        dmp_tree_height: usize,
        dmp_count: usize,
        has_minifier: bool,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let delta_merkle_proofs = (0..dmp_count)
            .map(|_| DeltaMerkleProofGadget::add_virtual_to::<C::Hasher, C::F, D>(&mut builder, dmp_tree_height))
            .collect::<Vec<_>>();

        for i in 1..delta_merkle_proofs.len() {
            builder.connect_hashes(delta_merkle_proofs[i - 1].new_root, delta_merkle_proofs[i].old_root);
        }

        let start_state_hash = delta_merkle_proofs[0].old_root;
        let end_state_hash = delta_merkle_proofs.last().unwrap().new_root;
        let combined_state_hash = builder.hash_two_to_one::<C::Hasher>(start_state_hash, end_state_hash);

        builder.register_public_inputs(&combined_state_hash.elements);

        let base_circuit_data = builder.build::<C>();

        let base_fingerprint = QHashOut(get_circuit_fingerprint_generic(&base_circuit_data.verifier_only));

        let minifier_chain = if has_minifier {
            Some(PsyProofMinifierDynamicChain::<D, C::F, C>::new_with_dynamic_constant_verifier(
                &base_circuit_data.verifier_only,
                &base_circuit_data.common,
                &[true, false],
            ))
        } else {
            None
        };

        Self {
            delta_merkle_proofs,
            base_circuit_data,
            base_fingerprint,
            minifier_chain,
            enable_minifier: has_minifier,
        }
    }

    pub fn is_minifier_enabled(&self) -> bool {
        self.enable_minifier && self.minifier_chain.is_some()
    }

    fn prove_base_inner(&self, delta_merkle_proofs: &[DeltaMerkleProofCore<QHashOut<C::F>>]) -> ProofWithPublicInputs<C::F, C, D> {
        let mut pw_base = PartialWitness::<C::F>::new();

        assert_eq!(
            self.delta_merkle_proofs.len(),
            delta_merkle_proofs.len(),
            "insufficient or too many delta merkle proofs provided as a witness to the placeholder circuit"
        );
        self.delta_merkle_proofs
            .iter()
            .zip(delta_merkle_proofs.iter())
            .for_each(|(gadget, proof)| {
                gadget.set_witness_core_proof_q(&mut pw_base, proof).unwrap();
            });

        self.base_circuit_data.prove(pw_base).unwrap()
    }
    pub fn prove_base(&self, delta_merkle_proofs: &[DeltaMerkleProofCore<QHashOut<C::F>>]) -> ProofWithPublicInputs<C::F, C, D> {
        if self.is_minifier_enabled() {
            let base_proof = self.prove_base_inner(delta_merkle_proofs);
            self.minifier_chain.as_ref().unwrap().prove(&base_proof).unwrap()
        } else {
            self.prove_base_inner(delta_merkle_proofs)
        }
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> CFCPlaceholderCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    pub fn prove_seq_filler(&self) -> ProofWithPublicInputs<C::F, C, D> {
        let height = self.delta_merkle_proofs[0].siblings.len();

        let mut simple_tree = SimpleMerkleTree::<C::Hasher, HashOut<C::F>>::new(height as u8);
        let max_leaves_mask = (1u64 << (height as u64)) - 1u64;

        let dmps = (0..self.delta_merkle_proofs.len())
            .map(|i| {
                let value = QHashOut::<C::F>::rand();
                let index =
                    ((i as u64) ^ (value.0.elements[0].to_canonical_u64() * (i as u64) * value.0.elements[1].to_canonical_u64())) & max_leaves_mask;
                simple_tree.set_leaf(index, value.0).into()
            })
            .collect::<Vec<_>>();

        self.prove_base(&dmps)
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D> for CFCPlaceholderCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        if self.is_minifier_enabled() {
            QHashOut(self.minifier_chain.as_ref().unwrap().get_fingerprint())
        } else {
            self.base_fingerprint
        }
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        if self.is_minifier_enabled() {
            self.minifier_chain.as_ref().unwrap().get_verifier_data()
        } else {
            &self.base_circuit_data.verifier_only
        }
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        if self.is_minifier_enabled() {
            self.minifier_chain.as_ref().unwrap().get_common_data()
        } else {
            &self.base_circuit_data.common
        }
    }
}

/*
impl<C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvable<CFCPlaceholderCircuitInput<C::F>, C, D>
    for CFCPlaceholderCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_standard(
        &self,
        input: &CFCPlaceholderCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        Ok(self.prove_base(
            input
        ))
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvableWithProofStoreSync<S, CFCPlaceholderCircuitInput<C::F>, C, D>
    for CFCPlaceholderCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_with_proof_store_sync(
        &self,
        _store: &S,
        input: &CFCPlaceholderCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_standard(input)
    }
}
*/
