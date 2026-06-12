use plonky2::{hash::hash_types::HashOutTarget, plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData}, config::{AlgebraicHasher, GenericConfig}}};
use psy_common_circuit::{builder::{hash::core::CircuitBuilderHashCore, pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates}}, proof_minifier::pm_core::get_circuit_fingerprint_generic};
use psy_client_common::data::qhashout::QHashOut;


pub struct AggStateTransitionLookalikeCircuit<C: GenericConfig<D>, const D: usize>
{
    pub input_hash: HashOutTarget,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> AggStateTransitionLookalikeCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let input_hash = builder.add_virtual_hash();
        let output_hash = builder.hash_two_to_one::<C::Hasher>(input_hash, input_hash);

        builder.register_public_inputs(&input_hash.elements);
        builder.register_public_inputs(&output_hash.elements);
        builder.add_psy_type_d_common_gates();
        pad_circuit_degree(&mut builder, 12);
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
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use psy_common_circuit::{circuits::traits::qstandard::QStandardCircuit, treeprover::{aggregation::{state_transition::AggStateTransitionCircuit, state_transition_dummy::AggStateTransitionDummyCircuit}, traits::TreeProverAggCircuit}};

    use crate::lookalikes::agg_state::AggStateTransitionLookalikeCircuit;

    #[test]
    fn check_agg_state_transition_lookalike(){
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;

    
        let agg_state_transition_lookalike = AggStateTransitionLookalikeCircuit::<C,D>::new();
        let agg_state_dummy = AggStateTransitionDummyCircuit::<C,D>::new();
        let agg_state = AggStateTransitionCircuit::<C,D>::new(&agg_state_dummy.circuit_data.common, agg_state_dummy.get_verifier_config_ref().constants_sigmas_cap.height());

        
        assert_eq!(
            agg_state_transition_lookalike.circuit_data.common,
            agg_state_dummy.get_common_circuit_data_ref().to_owned(),
            "Agg State Transition lookalike's common data does not match the real Dummy Agg State Transition common data",
        );
        
        assert_eq!(
            agg_state_transition_lookalike.circuit_data.common,
            agg_state.get_common_circuit_data_ref().to_owned(),
            "Agg State Transition lookalike's common data does not match the real Agg State Transition common data",
        );
    }
}