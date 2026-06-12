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
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::{
    common::witnesses::qrecursion::header::QRecursionAggStandardHeader,
    hash::{merkle::core::MerkleProofCore, traits::hasher::MerkleZeroHasher},
};

use crate::{
    builder::hash::core::CircuitBuilderHashCore,
    circuits::traits::qstandard::QStandardCircuit,
    proof_minifier::{pm_chain_dynamic::PsyProofMinifierDynamicChain, pm_core::get_circuit_fingerprint_generic},
    treeprover::qrecursion::standard::gadgets::verify_agg_proof::VerifyAggProofGadget,
};
#[derive(Debug)]
pub struct QRecursionStandardRootCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    verify_proof_tree_root_gadget: VerifyAggProofGadget<D>,

    // end circuit targets
    base_circuit_data: CircuitData<C::F, C, D>,
    base_fingerprint: QHashOut<C::F>,
    minifier_chain: Option<PsyProofMinifierDynamicChain<D, C::F, C>>,
    enable_minifier: bool,
    // end circuit data
}

impl<C: GenericConfig<D>, const D: usize> QRecursionStandardRootCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn is_minifier_enabled(&self) -> bool {
        self.enable_minifier && self.minifier_chain.is_some()
    }
}
impl<C: GenericConfig<D>, const D: usize> QRecursionStandardRootCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new_with_minifier(
        proof_tree_agg_common_data: &CommonCircuitData<C::F, D>,
        proof_tree_agg_verifier_data_cap_height: usize,
        known_proof_tree_circuit_whitelist_root: QHashOut<C::F>,
    ) -> Self {
        Self::new_with_config(
            proof_tree_agg_common_data,
            proof_tree_agg_verifier_data_cap_height,
            known_proof_tree_circuit_whitelist_root,
            true,
        )
    }
    pub fn new_without_minifier(
        proof_tree_agg_common_data: &CommonCircuitData<C::F, D>,
        proof_tree_agg_verifier_data_cap_height: usize,
        known_proof_tree_circuit_whitelist_root: QHashOut<C::F>,
    ) -> Self {
        Self::new_with_config(
            proof_tree_agg_common_data,
            proof_tree_agg_verifier_data_cap_height,
            known_proof_tree_circuit_whitelist_root,
            false,
        )
    }
    pub fn new_with_config(
        proof_tree_agg_common_data: &CommonCircuitData<C::F, D>,
        proof_tree_agg_verifier_data_cap_height: usize,
        known_proof_tree_circuit_whitelist_root: QHashOut<C::F>,

        has_minifier: bool,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let verify_proof_tree_root_gadget =
            VerifyAggProofGadget::add_virtual_to::<C, C::F>(&mut builder, proof_tree_agg_common_data, proof_tree_agg_verifier_data_cap_height);

        let known_proof_tree_circuit_whitelist_root_target = builder.constant_qhash(known_proof_tree_circuit_whitelist_root);

        // ensure the proof tree is using the correct, unmodified aggregation circuits
        builder.connect_hashes(
            known_proof_tree_circuit_whitelist_root_target,
            verify_proof_tree_root_gadget.agg_whitelist_merkle_proof.root,
        );

        let public_inputs_hash = verify_proof_tree_root_gadget.agg_proof_header_gadget.state_transition_end;

        builder.register_public_inputs(&public_inputs_hash.elements);

        let base_circuit_data = builder.build::<C>();

        let base_fingerprint = QHashOut(get_circuit_fingerprint_generic(&base_circuit_data.verifier_only));

        let minifier_chain = if has_minifier {
            Some(PsyProofMinifierDynamicChain::<D, C::F, C>::new_with_dynamic_constant_verifier(
                &base_circuit_data.verifier_only,
                &base_circuit_data.common,
                &[true, true, true, true],
            ))
        } else {
            None
        };

        Self {
            base_circuit_data,
            base_fingerprint,
            minifier_chain,
            enable_minifier: has_minifier,
            verify_proof_tree_root_gadget,
        }
    }

    fn prove_base_inner(
        &self,
        agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        agg_root_proof: &ProofWithPublicInputs<C::F, C, D>,
        agg_root_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();

        self.verify_proof_tree_root_gadget.set_witness(
            &mut pw,
            agg_whitelist_merkle_proof,
            agg_proof_header,
            agg_root_proof,
            agg_root_verifier_data,
        )?;

        self.base_circuit_data.prove(pw)
    }
    pub fn prove_base(
        &self,
        agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        agg_root_proof: &ProofWithPublicInputs<C::F, C, D>,
        agg_root_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        if self.is_minifier_enabled() {
            let base_proof = self.prove_base_inner(agg_whitelist_merkle_proof, agg_proof_header, agg_root_proof, agg_root_verifier_data)?;
            self.minifier_chain.as_ref().unwrap().prove(&base_proof)
        } else {
            self.prove_base_inner(agg_whitelist_merkle_proof, agg_proof_header, agg_root_proof, agg_root_verifier_data)
        }
    }

    pub fn verify_proof(&self, proof_with_pis: ProofWithPublicInputs<C::F, C, D>) -> anyhow::Result<()> {
        if self.is_minifier_enabled() {
            self.minifier_chain.as_ref().unwrap().verify(proof_with_pis)
        } else {
            self.base_circuit_data.verify(proof_with_pis)
        }
    }
}
impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for QRecursionStandardRootCircuit<C, D>
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
