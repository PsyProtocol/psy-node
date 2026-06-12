use plonky2::{hash::hash_types::HashOutTarget, plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData}, config::{AlgebraicHasher, GenericConfig}}};
use psy_config::PSY_NETWORK_MAGIC;
use psy_common_circuit::{builder::{hash::core::CircuitBuilderHashCore, pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates}}, proof_minifier::pm_core::get_circuit_fingerprint_generic};
use psy_client_common::data::qhashout::QHashOut;


pub struct EndCapLookalikeCircuit<C: GenericConfig<D>, const D: usize>
{
    pub input_hash: HashOutTarget,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> EndCapLookalikeCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let input_hash = builder.add_virtual_hash();
        let output_hash = builder.hash_two_to_one::<C::Hasher>(input_hash, input_hash);

        builder.register_public_inputs(&output_hash.elements);
        builder.add_psy_type_e_common_gates();
        pad_circuit_degree(&mut builder, 11);
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(
            &circuit_data.verifier_only,
        ));

        Self {
            input_hash,
            circuit_data,
            fingerprint,
        }
    }
}


#[cfg(test)]
mod tests {
    use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
    use psy_common_circuit::{circuits::traits::qstandard::QStandardCircuit, treeprover::qrecursion::standard::manager::portable::circuits::PortableQTreeRecursionCircuits};
    use psy_client_common::{config::network_constants::{PSY_NETWORK_MAGIC, UPS_CIRCUIT_WHITELIST_TREE_HEIGHT, UPS_SESSION_PROOF_TREE_HEIGHT}, data::qhashout::QHashOut};
    use psy_crypto::hash::{merkle::utils::simple_merkle_tree::SimpleMerkleTree, traits::hasher::PoseidonHasher};

    use crate::{lookalikes::end_cap::EndCapLookalikeCircuit, ups::circuits::{end_cap::UPSStandardEndCapCircuit, ups_cfc_deferred_tx::UPSCFCDeferredTransactionCircuit, ups_cfc_standard::UPSCFCStandardTransactionCircuit, ups_start::UPSStartSessionCircuit}};

    #[test]
    fn check_endcap_lookalike(){
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = GoldilocksField;
    
        let ups_start = UPSStartSessionCircuit::<C,D>::new();
        let ups_cfc_standard_tx = UPSCFCStandardTransactionCircuit::<C,D>::new();
        let ups_cfc_deferred_tx = UPSCFCDeferredTransactionCircuit::<C,D>::new();
        let network_magic = PSY_NETWORK_MAGIC;
        let mut ups_circuit_whitelist_proofs =
            SimpleMerkleTree::<PoseidonHasher, QHashOut<F>>::gen_fast_tree_inclusion_proofs(
                UPS_CIRCUIT_WHITELIST_TREE_HEIGHT,
                &[
                    ups_start.get_fingerprint(),
                    ups_cfc_standard_tx.get_fingerprint(),
                    ups_cfc_deferred_tx.get_fingerprint(),
                ],
            )
            .unwrap();
        let _ups_cfc_deferred_tx_whitelist_proof = ups_circuit_whitelist_proofs.pop().unwrap();
        let ups_cfc_standard_tx_whitelist_proof = ups_circuit_whitelist_proofs.pop().unwrap();
        let _ups_start_whitelist_proof = ups_circuit_whitelist_proofs.pop().unwrap();

        let ups_circuit_whitelist_root = ups_cfc_standard_tx_whitelist_proof.root;

        let proof_tree_agg_circuits = PortableQTreeRecursionCircuits::<C,D>::new(
            UPS_SESSION_PROOF_TREE_HEIGHT as usize,
            1,
            ups_cfc_deferred_tx
                .circuit_data
                .verifier_only
                .constants_sigmas_cap
                .height(),
            &ups_cfc_deferred_tx.circuit_data.common,
        );
        let ups_end_cap = UPSStandardEndCapCircuit::<C,D>::new_with_minifier(
            &proof_tree_agg_circuits.circuit_set.two_agg_circuit.circuit_data.common,
            proof_tree_agg_circuits.circuit_set.two_agg_circuit.get_verifier_config_ref().constants_sigmas_cap.height(),
            network_magic,
            ups_circuit_whitelist_root,
            proof_tree_agg_circuits
                .circuit_inclusion_proofs
                .circuit_whitelist_tree_root,
        );

        let fake_end_cap = EndCapLookalikeCircuit::<C,D>::new();
        assert_eq!(
            fake_end_cap.circuit_data.common,
            ups_end_cap.get_common_circuit_data_ref().to_owned(),
            "end cap lookalike's common data does not match the real end cap common data",
        );


    }
}