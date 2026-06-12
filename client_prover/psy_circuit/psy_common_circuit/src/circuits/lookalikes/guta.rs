use plonky2::{hash::hash_types::HashOutTarget, plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData}, config::{AlgebraicHasher, GenericConfig}}};
use psy_common_circuit::{builder::{hash::core::CircuitBuilderHashCore, pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates}}, proof_minifier::pm_core::get_circuit_fingerprint_generic};
use psy_client_common::data::qhashout::QHashOut;


pub struct GUTALookalikeCircuit<C: GenericConfig<D>, const D: usize>
{
    pub input_hash: HashOutTarget,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> GUTALookalikeCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let input_hash = builder.add_virtual_hash();
        let output_hash = builder.hash_two_to_one::<C::Hasher>(input_hash, input_hash);

        builder.register_public_inputs(&output_hash.elements);
        builder.add_psy_type_c_common_gates();
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
    use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;
    use psy_client_common::data::qhashout::QHashOut;

    use crate::{guta::circuits::verify_two_end_cap::GUTAVerifyTwoEndCapCircuit, lookalikes::{end_cap::EndCapLookalikeCircuit, guta::GUTALookalikeCircuit}};

    #[test]
    fn check_guta_lookalike(){
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;

    
        let end_cap_lookalike = EndCapLookalikeCircuit::<C,D>::new();
        let two_guta = GUTAVerifyTwoEndCapCircuit::<C,D>::new(
            &end_cap_lookalike.circuit_data.common, 
            end_cap_lookalike.circuit_data.verifier_only.constants_sigmas_cap.height(),
            QHashOut::rand()
        );
        let guta_lookalike = GUTALookalikeCircuit::<C,D>::new();
        
        assert_eq!(
            two_guta.get_common_circuit_data_ref().to_owned(),
            guta_lookalike.circuit_data.common,
            "GUTA lookalike's common data does not match the real GUTA common data",
        );
    }
}