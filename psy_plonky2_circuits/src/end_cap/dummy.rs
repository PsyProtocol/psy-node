use parth_core::{crypto::hash::traits::{FieldQHasher, MerkleZeroHasher, QFieldHashable}, felt::QFelt64, pgoldilocks::QHashOut, protocol::core_types::QFHashBase};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget}, iop::witness::{PartialWitness, WitnessWrite}, plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    }
};
use psy_data::{guta::stats::GUTAStats, v1::qdata::{user::PQEDUserLeaf, user_end_cap_result::PUPSEndCapResultCompact}};
use psy_plonky2_basic_helpers::builder::pad_circuit::{pad_circuit_degree, CircuitBuilderQEDCommonGates};
use crate::{proof_minifier::{pm_chain_dynamic::QEDProofMinifierDynamicChain, pm_core::get_circuit_fingerprint_generic}, qstandard::QStandardCircuit};
use plonky2::field::types::Field;

#[derive(Debug)]
pub struct DummyUPSStandardEndCapCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub dummy_public_inputs: HashOutTarget,

    // end circuit targets
    pub base_circuit_data: CircuitData<C::F, C, D>,
    pub base_fingerprint: QHashOut<C::F>,
    pub minifier_chain: Option<QEDProofMinifierDynamicChain<D, C::F, C>>,
    pub enable_minifier: bool,
    // end circuit data
}

impl<C: GenericConfig<D> + 'static, const D: usize> DummyUPSStandardEndCapCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn is_minifier_enabled(&self) -> bool {
        self.enable_minifier && self.minifier_chain.is_some()
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> DummyUPSStandardEndCapCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new_with_minifier(
    ) -> Self {
        Self::new_with_config(
            true,
        )
    }
    pub fn new_without_minifier(
    ) -> Self {
        Self::new_with_config(
            false,
        )
    }
    pub fn new_with_config(
        has_minifier: bool,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let dummy_public_inputs = builder.add_virtual_hash();
        
        builder.register_public_inputs(&dummy_public_inputs.elements);
        builder.add_qed_type_e_common_gates();
        pad_circuit_degree(&mut builder, 11);

        let base_circuit_data = builder.build::<C>();

        let base_fingerprint = QHashOut(get_circuit_fingerprint_generic(
            &base_circuit_data.verifier_only,
        ));

        let minifier_chain = if has_minifier {
            Some(
                QEDProofMinifierDynamicChain::<D, C::F, C>::new_with_dynamic_constant_verifier(
                    &base_circuit_data.verifier_only,
                    &base_circuit_data.common,
                    &[false, false],
                ),
            )
        } else {
            None
        };

        Self {
            base_circuit_data,
            base_fingerprint,
            minifier_chain,
            enable_minifier: has_minifier,
            dummy_public_inputs,
        }
    }

    fn prove_base_inner(
        &self,
        dummy_public_inputs: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        pw.set_hash_target(self.dummy_public_inputs, dummy_public_inputs.0)?;
        self.base_circuit_data.prove(pw)
    }
    pub fn prove_base(
        &self,        
        dummy_public_inputs: QHashOut<C::F>,

    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        if self.is_minifier_enabled() {
            let base_proof = self.prove_base_inner(
                dummy_public_inputs,
            )?;
            self.minifier_chain.as_ref().unwrap().prove(&base_proof)
        } else {
            self.prove_base_inner(
                dummy_public_inputs,
            )
        }
    }

    pub fn verify_proof(&self, proof_with_pis: ProofWithPublicInputs<C::F, C, D>,) -> anyhow::Result<()> {
        if self.is_minifier_enabled() {
            self.minifier_chain.as_ref().unwrap().verify(proof_with_pis)
        }else{
            self.base_circuit_data.verify(proof_with_pis)
        }
    }

    pub fn generate_proof_for_inputs(
        &self,
        start_user_leaf: &PQEDUserLeaf<C::F, QHashOut<C::F>>,
        new_user_state_root: QHashOut<C::F>,
        new_checkpoint_id: u64,
        new_checkpoint_root: QHashOut<C::F>,
        number_of_transactions: u64,
        slots_modified: u64,
        global_user_tree_height: u8,
    ) -> anyhow::Result<(PQEDUserLeaf<C::F, QHashOut<C::F>>, QHashOut<C::F>, GUTAStats<C::F>, PUPSEndCapResultCompact<C::F, QHashOut<C::F>>,ProofWithPublicInputs<C::F, C, D>)> where C::Hasher: FieldQHasher<C::F, QHashOut<C::F>>, C::F: QFelt64, QHashOut<<C as GenericConfig<D>>::F>: QFHashBase<<C as GenericConfig<D>>::F>{


        let old_user_leaf_hash = start_user_leaf.qfhash::<C::Hasher>();
        let mut new_user_leaf = start_user_leaf.clone();
        new_user_leaf.last_checkpoint_id = C::F::from_noncanonical_u64(new_checkpoint_id);
        new_user_leaf.nonce = new_user_leaf.nonce + C::F::from_noncanonical_u64(1);
        new_user_leaf.user_state_tree_root = new_user_state_root;
        let new_user_leaf_hash = new_user_leaf.qfhash::<C::Hasher>();
        let guta_stats = GUTAStats{
            fees_collected: C::F::from_noncanonical_u64(1000),
            user_ops_processed: C::F::from_noncanonical_u64(1),
            total_transactions: C::F::from_noncanonical_u64(number_of_transactions),
            slots_modified: C::F::from_noncanonical_u64(slots_modified),
        };


        let end_cap_result = PUPSEndCapResultCompact {
            start_user_leaf_hash: old_user_leaf_hash,
            end_user_leaf_hash: new_user_leaf_hash,
            checkpoint_tree_root_hash: new_checkpoint_root,
            user_id: new_user_leaf.user_id,
        };

        let guta_hash = end_cap_result.qfhash_with_guta_height::<C::Hasher>(global_user_tree_height);
        let public_inputs_expected = C::Hasher::q_two_to_one(guta_hash, guta_stats.qfhash::<C::Hasher>());
        let proof = self.prove_base(
            public_inputs_expected,
        )?;
        Ok((new_user_leaf, public_inputs_expected, guta_stats, end_cap_result, proof))

    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for DummyUPSStandardEndCapCircuit<C, D>
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




#[cfg(test)]
mod tests {
    use plonky2::{field::goldilocks_field::GoldilocksField, plonk::{config::PoseidonGoldilocksConfig, verifier_v2::verify_standard_proof}};
    use psy_plonky2_basic_helpers::{lookalike::standard::get_end_cap_type_e_common_data, verifier::alt::AltVerifierOnlyCircuitData};

    use super::*;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    type F = GoldilocksField;
    #[test]
    fn test_dummy_ups_standard_end_cap_circuit() {
        let public_inputs_hash = QHashOut::<F>::rand();
        let circuit = DummyUPSStandardEndCapCircuit::<C, D>::new_without_minifier();
        let proof = circuit.prove_base(public_inputs_hash).unwrap();
        assert_eq!(public_inputs_hash.0.elements.to_vec(), proof.public_inputs);
        circuit.verify_proof(proof.clone()).unwrap();
        println!("dummy_fingerprint: {} ({:?})", serde_json::to_string(&circuit.get_fingerprint()).unwrap(), circuit.get_fingerprint());
        //println!("common_data: {:#?}", circuit.get_common_circuit_data_ref());
        let alt_verifier_data = AltVerifierOnlyCircuitData::<F>::new_from_verifier_data(circuit.get_verifier_config_ref());

        println!("alt_verifier_data: {}", serde_json::to_string(&alt_verifier_data).unwrap());
        let common_data_gen = get_end_cap_type_e_common_data::<C,D>();
        //println!("common_data_gen: {:#?}", common_data_gen);
        verify_standard_proof(
            &proof,
            &circuit.get_verifier_config_ref(),
            &common_data_gen,
        ).unwrap();
    }
}