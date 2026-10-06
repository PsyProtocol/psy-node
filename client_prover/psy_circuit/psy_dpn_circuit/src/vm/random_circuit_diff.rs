// Circuit-side twin of the op-level differential fuzz: the SAME randomly
// generated programs (psy_vm::dpn::vm::fuzz_support, one generator for both
// harnesses) are built into a real circuit with `SimpleDPNBuilder`, proven
// and verified, and every definition's value is registered as a public
// input and compared against the native mirror:
//
//   mirror-accepted program  => prove must succeed and every public input
//                               must equal the mirror's pool value;
//   mirror-rejected program  => prove must FAIL (rejection parity — the
//                               circuit must not be satisfiable where the
//                               native semantics reject).
//
// Proving is expensive: the default is 40 seeds in debug and 10_000 in
// release; override with PSY_DPN_CIRCUIT_FUZZ_ITERS and
// reproduce a single seed with PSY_DPN_CIRCUIT_FUZZ_SEED.

use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    hash::hash_types::HashOutTarget,
    iop::target::Target,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
};

use psy_vm::dpn::ops::op_types::DPNBuiltInDataType;
use psy_vm::dpn::vm::fuzz_support::{mirror_eval, program_for_seed, dump_program, Program};

use super::ops::SimpleDPNBuilder;

const D: usize = 2;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

/// Register every definition's value as public inputs, in definition order,
/// and return the expected value sequence from the mirror pools in the same
/// order (scalar = 1 value, hashes = 4, arrays = their length).
fn register_all_public_inputs(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    executor: &mut SimpleDPNBuilder<F, D>,
    program: &Program,
    expected: &mut Vec<u64>,
) {
    let mirror = mirror_eval(program).ok(); // caller ensures Ok on the proved path
    for def in &program.defs {
        let id = psy_vm::dpn::ops::op_types::encode_indexed_op_id(def.data_type, def.index);
        match def.data_type {
            DPNBuiltInDataType::Target => {
                let t = executor.resolve_target(id);
                builder.register_public_input(t);
                if let Some(m) = &mirror {
                    expected.push(m.targets[def.index]);
                }
            }
            DPNBuiltInDataType::U32Target => {
                let t = executor.resolve_u32(builder, id);
                builder.register_public_input(t.0);
                if let Some(m) = &mirror {
                    expected.push(m.u32s[def.index] as u64);
                }
            }
            DPNBuiltInDataType::Bool => {
                let b = executor.resolve_bool(builder, id);
                builder.register_public_input(b.target);
                if let Some(m) = &mirror {
                    expected.push(m.bools[def.index] as u64);
                }
            }
            DPNBuiltInDataType::HashOut => {
                let h: HashOutTarget = executor.resolve_hash(id);
                for e in h.elements {
                    builder.register_public_input(e);
                }
                if let Some(m) = &mirror {
                    expected.extend_from_slice(&m.hashes[def.index]);
                }
            }
            DPNBuiltInDataType::BoolArray => {
                let arr = executor.resolve_bool_array(id);
                for b in arr {
                    builder.register_public_input(b.target);
                }
                if let Some(m) = &mirror {
                    expected.extend(m.bool_arrays[def.index].iter().map(|&b| b as u64));
                }
            }
            DPNBuiltInDataType::U32TargetArray => {
                let arr = executor.resolve_u32_array(id);
                for w in arr {
                    builder.register_public_input(w.0);
                }
                if let Some(m) = &mirror {
                    expected.extend(m.u32_arrays[def.index].iter().map(|&w| w as u64));
                }
            }
            DPNBuiltInDataType::TargetArray => {
                let arr: Vec<Target> = executor.resolve_target_array(id);
                for t in arr {
                    builder.register_public_input(t);
                }
                if let Some(m) = &mirror {
                    expected.extend_from_slice(&m.target_arrays[def.index]);
                }
            }
            DPNBuiltInDataType::HashOut160 | DPNBuiltInDataType::Unknown => {
                unreachable!("fuzzer never generates these lanes")
            }
        }
    }
}

#[test]
fn random_op_graphs_match_circuit() {
    let iters: u64 = std::env::var("PSY_DPN_CIRCUIT_FUZZ_ITERS")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(if cfg!(debug_assertions) { 40 } else { 2_000 });
    let seeds: Vec<u64> = if let Ok(raw) = std::env::var("PSY_DPN_CIRCUIT_FUZZ_SEED") {
        vec![raw.trim().parse().expect("PSY_DPN_CIRCUIT_FUZZ_SEED must be a u64")]
    } else {
        let base = 0x5EED_2026_0923_u64;
        (0..iters).map(|i| base ^ i.wrapping_mul(0x9E37_79B9_7F4A_7C15)).collect()
    };

    let (mut proved, mut unsat) = (0u64, 0u64);
    // Secp256k1Verify circuits need the ECC config and dominate proving
    // time; at most TEN secp seeds run per pass (covered further by the
    // dedicated KAT/e2e tests and the witness-side fuzz). Set
    // PSY_DPN_CIRCUIT_FUZZ_SECP=1 to run every secp seed.
    let include_all_secp = std::env::var("PSY_DPN_CIRCUIT_FUZZ_SECP").is_ok();
    let mut secp_budget = 10usize;
    for seed in seeds.clone() {
        let program = program_for_seed(seed);
        let mirror = mirror_eval(&program);
        let has_secp = program.defs.iter().any(|d| {
            matches!(d.op_type, psy_vm::dpn::ops::op_types::DPNOpType::Secp256k1Verify)
        });
        if has_secp && !include_all_secp {
            if secp_budget == 0 {
                continue;
            }
            secp_budget -= 1;
        }

        let config = if has_secp {
            CircuitConfig::standard_ecc_config()
        } else {
            CircuitConfig::standard_recursion_config()
        };

        // Build + prove in one closure: a mirror-rejected program may abort
        // at BUILD time (a constant zero divisor inverts inside
        // builder.div), and a build panic is as good as a prove failure for
        // the rejection-parity check - either way no proof exists.
        let build_and_prove = || {
            let mut builder = plonky2::plonk::circuit_builder::CircuitBuilder::<F, D>::new(config.clone());
            let n_inputs = program
                .defs
                .iter()
                .filter(|d| {
                    matches!(
                        d.op_type,
                        psy_vm::dpn::ops::op_types::DPNOpType::InputTarget
                            | psy_vm::dpn::ops::op_types::DPNOpType::U32InputTarget
                            | psy_vm::dpn::ops::op_types::DPNOpType::BoolInputTarget
                    )
                })
                .count();
            let input_targets: Vec<Target> = (0..n_inputs).map(|_| builder.add_virtual_target()).collect();
            let mut executor = SimpleDPNBuilder::new_with_contract_ctx(
                input_targets.clone(),
                builder.zero(),
                builder.zero(),
                builder.zero(),
                builder.zero(),
                builder.zero(),
                HashOutTarget {
                    elements: [builder.zero(); 4],
                },
                HashOutTarget {
                    elements: [builder.zero(); 4],
                },
            );
            for def in &program.defs {
                executor.process_var_def(&mut builder, def);
            }

            let mut expected = Vec::new();
            register_all_public_inputs(&mut builder, &mut executor, &program, &mut expected);

            let data = builder.build::<C>();
            let mut pw = PartialWitness::new();
            for (t, v) in input_targets.iter().zip(&program.input_values) {
                pw.set_target(*t, F::from_noncanonical_u64(*v)).unwrap();
            }
            (data.prove(pw), data, expected)
        };

        match mirror {
            Ok(_) => {
                let (proof, data, expected) = build_and_prove();
                let proof = proof
                    .unwrap_or_else(|e| panic!("mirror-accepted program must prove (seed {seed}): {e}\n{}", dump_program(&program)));
                data.verify(proof.clone()).expect("proof must verify");
                for (i, (got, want)) in proof.public_inputs.iter().zip(&expected).enumerate() {
                    assert_eq!(
                        *got,
                        F::from_noncanonical_u64(*want),
                        "circuit public input #{i} mismatch (seed {seed}): got {} want {want}\n{}",
                        got.to_canonical_u64(),
                        dump_program(&program)
                    );
                }
                proved += 1;
            }
            Err(_) => {
                let attempted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(build_and_prove));
                let rejected = match attempted {
                    Err(_) => true, // build-time abort
                    Ok((Err(_), _, _)) => true, // unsatisfiable
                    Ok((Ok(_), _, _)) => false,
                };
                assert!(
                    rejected,
                    "mirror-rejected program must not yield a proof (seed {seed})\n{}",
                    dump_program(&program)
                );
                unsat += 1;
            }
        }
    }
    println!("random op graph circuit differential: {} seeds ({proved} proved, {unsat} unsatisfiable)", seeds.len());
}
