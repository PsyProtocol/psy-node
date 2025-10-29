use plonky2::plonk::{
    circuit_builder::CircuitBuilder,
    circuit_data::{CircuitConfig, CircuitData, CommonCircuitData},
    config::{AlgebraicHasher, GenericConfig},
};

use crate::{
    builder::{hash::core::CircuitBuilderHashCore, pad_circuit::{pad_circuit_degree, CircuitBuilderQEDCommonGates}}, lookalike::types::QCircuitCommonGatesType}
;

pub fn get_lookalike_custom<C: GenericConfig<D>, const D: usize>(
    common_gates_type: QCircuitCommonGatesType,
    degree: usize,
    public_inputs: usize,
) -> CircuitData<C::F, C, D> where C::Hasher: AlgebraicHasher<C::F> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<C::F, D>::new(config);
    let input_hash = builder.add_virtual_hash();
    let output_hash = builder.hash_two_to_one::<C::Hasher>(input_hash, input_hash);

    for _ in 0..public_inputs {
        builder.register_public_input(output_hash.elements[0]);
    }
    match common_gates_type {
        QCircuitCommonGatesType::A => {
            builder.add_qed_type_a_common_gates(None);
        }
        QCircuitCommonGatesType::B => builder.add_qed_type_b_common_gates(),
        QCircuitCommonGatesType::C => builder.add_qed_type_c_common_gates(),
        QCircuitCommonGatesType::D => builder.add_qed_type_d_common_gates(),
        QCircuitCommonGatesType::E => builder.add_qed_type_e_common_gates(),
        QCircuitCommonGatesType::F => builder.add_qed_type_f_common_gates(),
    };
    pad_circuit_degree(&mut builder, degree - 1);
    let circuit_data = builder.build::<C>();

    circuit_data
}


pub fn get_lookalike_custom_common<C: GenericConfig<D>, const D: usize>(
    common_gates_type: QCircuitCommonGatesType,
    degree: usize,
    public_inputs: usize,
) -> CommonCircuitData<C::F, D> where C::Hasher: AlgebraicHasher<C::F> {
    get_lookalike_custom::<C,D>(common_gates_type, degree, public_inputs).common
}
