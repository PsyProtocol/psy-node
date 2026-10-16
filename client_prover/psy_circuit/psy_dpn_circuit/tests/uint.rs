use plonky2::{
    field::{goldilocks_field::GoldilocksField as F, types::{Field, Field64}},
    hash::hash_types::HashOutTarget,
    iop::{generator::{ConstantGenerator, SimpleGenerator, WitnessGeneratorRef}, target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData}, config::PoseidonGoldilocksConfig},
};
use psy_dpn_circuit::vm::ops::SimpleDPNBuilder;
use psy_vm::dpn::{
    ops::{context_trait::DPNContext, exec_context::QExecContext, op_types::DPNOpType, uint::{Uint, U128Value, U256Value, U64Value}},
    vm::compile::PsyCompileResult,
};

struct CastCircuit {
    data: CircuitData<F, PoseidonGoldilocksConfig, 2>,
    input: Target,
    split_bits: Vec<BoolTarget>,
    split_integer: Target,
    dummy_row: usize,
}

fn build_cast_circuit() -> CastCircuit {
    let mut ctx = QExecContext::new();
    let input = ctx.add_input();
    let value = U256Value::from_felt(&mut ctx, input);
    let function = PsyCompileResult::compile_exec("cast".into(), 0, &ctx.store, &ctx, &value.0);
    let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
    let input = builder.add_virtual_target();
    let zero = builder.zero();
    let hash = HashOutTarget { elements: [zero; 4] };
    let mut circuit = SimpleDPNBuilder::new_with_contract_ctx(vec![input], zero, zero, zero, zero, zero, hash, hash);
    let mut main_split: Option<(Vec<BoolTarget>, Target)> = None;
    for definition in &function.definitions {
        circuit.process_var_def(&mut builder, definition);
        if definition.op_type == DPNOpType::SplitBits && definition.inputs[0] == 64 {
            assert!(main_split.is_none(), "expected exactly one 64-bit SplitBits definition");
            let bits = circuit.bool_arrays[definition.index].as_ref().unwrap().clone();
            main_split = Some((bits, circuit.resolve_target(definition.inputs[1])));
        }
    }
    let (split_bits, split_integer) = main_split.expect("the felt input must be decomposed by a 64-bit SplitBits");
    assert_eq!(split_bits.len(), 64);
    assert_eq!(split_integer, input, "the 64-bit decomposition must consume the raw felt input");
    for assertion in &function.assertions { builder.connect(circuit.resolve_target(assertion.left), circuit.resolve_target(assertion.right)); }
    let dummy_row = builder.add_gate(plonky2::gates::noop::NoopGate, vec![]);
    let data = builder.build::<PoseidonGoldilocksConfig>();
    CastCircuit { data, input, split_bits, split_integer, dummy_row }
}

/// Write `value`'s little-endian decomposition into every wire of the split's
/// `BaseSumGate` rows, zero-filling the limb columns beyond the 64 bits that
/// were drained and asserted zero at circuit build time.
fn set_split_rows(witness: &mut PartialWitness<F>, split_bits: &[BoolTarget], num_limbs: usize, value: u64) {
    let mut rows = Vec::new();
    for (position, bit) in split_bits.iter().enumerate() {
        let Target::Wire(wire) = bit.target else { panic!("split bit must be a gate wire") };
        assert_eq!(wire.column, 1 + position % num_limbs, "BaseSumGate limbs start at column 1");
        if rows.last().copied() != Some(wire.row) { rows.push(wire.row); }
    }
    assert!(rows.len() * num_limbs >= split_bits.len());
    for (rank, row) in rows.iter().enumerate() {
        let mut sum = 0u64;
        for limb in 0..num_limbs {
            let position = rank * num_limbs + limb;
            let digit = if position < split_bits.len() { (value >> position) & 1 } else { 0 };
            sum |= digit << limb;
            witness.set_target(Target::wire(*row, 1 + limb), F::from_canonical_u64(digit)).unwrap();
        }
        witness.set_target(Target::wire(*row, 0), F::from_canonical_u64(sum)).unwrap();
    }
}

fn neutralize_main_split_generator(data: &mut CircuitData<F, PoseidonGoldilocksConfig, 2>, split_integer: Target, dummy_row: usize) {
    let mut neutralized = 0;
    for generator in &mut data.prover_only.generators {
        if generator.0.id() == "WireSplitGenerator" && generator.0.watch_list() == vec![split_integer] {
            *generator = WitnessGeneratorRef::new(ConstantGenerator { row: dummy_row, wire_index: 0, constant_index: 0, constant: F::ZERO }.adapter());
            neutralized += 1;
            break;
        }
    }
    assert_eq!(neutralized, 1, "the felt input decomposition must have a WireSplitGenerator");
}

#[test]
fn u256_felt_conversion_rejects_modulus_alias_with_a_malicious_generator() {
    let mut circuit = build_cast_circuit();
    // BaseSumGate::new_from_config: min(log2(p-1) = 63, num_routed_wires - 1) limbs per row.
    let num_limbs = 63usize.min(circuit.data.common.config.num_routed_wires - 1);
    neutralize_main_split_generator(&mut circuit.data, circuit.split_integer, circuit.dummy_row);
    let data = &circuit.data;

    // Control: the same neutralized circuit with the canonical decomposition of
    // zero still proves, so a forged-run failure cannot come from an incomplete
    // witness left by the removed generator.
    let mut witness = PartialWitness::new();
    witness.set_target(circuit.input, F::ZERO).unwrap();
    set_split_rows(&mut witness, &circuit.split_bits, num_limbs, 0);
    let proof = data.prove(witness).expect("the canonical decomposition of zero must still prove");
    data.verify(proof).unwrap();

    // Attack: with the input's generator neutralized, hand the circuit the
    // decomposition of 0 as p = 2^64 - 2^32 + 1 (low = 1, high = u32::MAX).
    let mut witness = PartialWitness::new();
    witness.set_target(circuit.input, F::ZERO).unwrap();
    set_split_rows(&mut witness, &circuit.split_bits, num_limbs, F::ORDER);
    let error = data.prove(witness).expect_err("a forged decomposition of zero as p must not prove");
    let message = format!("{error:?}");
    println!("forged decomposition rejected: {message}");
    assert!(!message.contains("was not generated"), "failure must not be a missing witness: {message}");
    assert!(!message.contains("generators weren't run"), "failure must not be an unrun generator: {message}");
    // PartitionWitness merges every `connect` (assertion) into one partition; the
    // noncanonical-decomposition assertion forces value 1 into the constant-zero
    // partition, so the constraint failure surfaces as a conflicting assignment.
    assert!(message.contains("set twice with different values: 0 != 1"), "expected the noncanonical-decomposition assertion (a copy constraint into the constant-zero partition) to be violated, got: {message}");
}

#[test]
fn u256_felt_conversion_accepts_honest_decompositions() {
    let circuit = build_cast_circuit();
    for value in [0u64, 5, F::ORDER - 1] {
        let mut witness = PartialWitness::new();
        witness.set_target(circuit.input, F::from_canonical_u64(value)).unwrap();
        let proof = circuit.data.prove(witness).unwrap();
        circuit.data.verify(proof).unwrap();
    }
}

/// The original u256 oracle test, instantiated for every width: the same
/// xorshift stream drives symbolic ops and an independent fixed-width oracle.
macro_rules! fixed_width_oracle_test {
    ($test_name:ident, $value_alias:ident, $n:literal, $oracle:ty) => {
        #[test]
        fn $test_name() {
            use psy_vm::dpn::{eval::{cache::SimpleEvalCache, simple::DummyContextEvalInput, traits::ContextEval}};
            let mut ctx = QExecContext::new();
            let a_limbs = std::array::from_fn(|_| ctx.add_u32_input());
            let a = $value_alias::from_limbs(&mut ctx, a_limbs);
            let b_limbs = std::array::from_fn(|_| ctx.add_u32_input());
            let b = $value_alias::from_limbs(&mut ctx, b_limbs);
            let add = a.add(&mut ctx, b);
            let sub = a.sub(&mut ctx, b);
            let mul = a.mul(&mut ctx, b);
            let and = a.bitand(&mut ctx, b);
            let xor = a.bitxor(&mut ctx, b);
            let mut seed = 0x7562_3536u64;
            for _ in 0..32 {
                let mut next = || { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed as u32 };
                let host_a = Uint::<$n>(std::array::from_fn(|_| next()));
                let host_b = Uint::<$n>(std::array::from_fn(|_| next()));
                let oracle = |v: Uint<$n>| <$oracle>::from_le_slice(&v.0.iter().flat_map(|limb| limb.to_le_bytes()).collect::<Vec<_>>());
                let oa = oracle(host_a);
                let ob = oracle(host_b);
                let (expected_add, _) = oa.overflowing_add(ob);
                let (expected_sub, _) = oa.overflowing_sub(ob);
                let (expected_mul, _) = oa.overflowing_mul(ob);
                let input = DummyContextEvalInput::new(host_a.0.into_iter().chain(host_b.0).map(u64::from).collect());
                let mut cache = SimpleEvalCache::new();
                for (value, expected) in [(add, expected_add), (sub, expected_sub), (mul, expected_mul), (and, oa & ob), (xor, oa ^ ob)] {
                    let limbs = value.0.map(|limb| ctx.store.resolve_felt_ref_cached(limb, &input, &mut cache) as u32);
                    assert_eq!(oracle(Uint::<$n>(limbs)), expected);
                }
            }
        }
    };
}

fixed_width_oracle_test!(u64_symbolic_arithmetic_matches_independent_fixed_width_oracle, U64Value, 2, alloy_primitives::U64);
fixed_width_oracle_test!(u128_symbolic_arithmetic_matches_independent_fixed_width_oracle, U128Value, 4, alloy_primitives::U128);
fixed_width_oracle_test!(u256_symbolic_arithmetic_matches_independent_fixed_width_oracle, U256Value, 8, alloy_primitives::U256);

#[test]
fn u64_felt_cast_and_add_proves_as_a_circuit() {
    // Width spot-check of the generic expansion: a felt -> u64 cast followed by
    // a checked add proves and verifies end-to-end through the circuit builder.
    let mut ctx = QExecContext::new();
    let input = ctx.add_input();
    let value = U64Value::from_felt(&mut ctx, input);
    let one = U64Value::constant(&mut ctx, Uint([1, 0]));
    let sum = value.add(&mut ctx, one);
    let function = PsyCompileResult::compile_exec("u64".into(), 0, &ctx.store, &ctx, &sum.0);
    let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
    let input = builder.add_virtual_target();
    let zero = builder.zero();
    let hash = HashOutTarget { elements: [zero; 4] };
    let mut circuit = SimpleDPNBuilder::new_with_contract_ctx(vec![input], zero, zero, zero, zero, zero, hash, hash);
    for definition in &function.definitions {
        circuit.process_var_def(&mut builder, definition);
    }
    for assertion in &function.assertions {
        builder.connect(circuit.resolve_target(assertion.left), circuit.resolve_target(assertion.right));
    }
    let data = builder.build::<PoseidonGoldilocksConfig>();
    for value in [0u64, 5, F::ORDER - 1] {
        let mut witness = PartialWitness::new();
        witness.set_target(input, F::from_canonical_u64(value)).unwrap();
        let proof = data.prove(witness).unwrap();
        data.verify(proof).unwrap();
    }
}
