use plonky2::plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig};
use psy_plonky2_common_circuits::hash::keccak::keccak256_u32_words_be_abi;

fn main() {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as plonky2::plonk::config::GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let mut input_targets = Vec::with_capacity(16);
    for _ in 0..16 {
        input_targets.push(builder.add_virtual_target());
    }
    let out = keccak256_u32_words_be_abi(&mut builder, &input_targets);
    for limb in out {
        builder.register_public_input(limb.0);
    }

    println!("num_gates_before_build={}", builder.num_gates());
    let data = builder.build::<C>();
    println!("degree_bits={} degree={}", data.common.degree_bits(), data.common.degree());
}
