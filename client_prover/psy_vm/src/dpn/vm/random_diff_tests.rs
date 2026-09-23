// Witness-side harness for the op-level differential fuzz: executes the
// randomly generated programs (see `fuzz_support`) on
// `SimpleDPNExecutor` — the VM's witness-generation core — and requires
// identical pools on acceptance and identical rejection classes on
// failure. The circuit-side twin lives in psy_dpn_circuit.
//
// Reproduce a failure:
//   PSY_VM_RANDOM_GRAPH_SEED=<seed> cargo test -p psy_vm random_op_graphs_match_native_execution
// Longer fuzzing runs:
//   PSY_VM_RANDOM_GRAPH_ITERS=100000 cargo test -p psy_vm random_op_graphs_match_native_execution

use plonky2::field::{
    goldilocks_field::GoldilocksField,
    types::{Field, PrimeField64},
};

use super::fuzz_support::{
    classify_rejection, dump_program, expected_scalar_outputs, mirror_eval, panic_message,
    program_definition, program_for_seed, pools_diff, MirrorErr, MirrorPools, Program,
};
use crate::dpn::eval::executor::{
    ExecutionContext, InMemoryStateBackend, VmExecutor,
};
use crate::dpn::vm::exec::SimpleDPNExecutor;

// ---------- executor harness ----------

fn run_executor(program: &Program) -> Result<SimpleDPNExecutor<GoldilocksField>, String> {
    let inputs = program
        .input_values
        .iter()
        .map(|v| GoldilocksField::from_canonical_u64(*v))
        .collect::<Vec<_>>();
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut executor = SimpleDPNExecutor::<GoldilocksField>::new_with_contract_ctx(
            inputs,
            GoldilocksField::ZERO,
            GoldilocksField::ZERO,
            GoldilocksField::ZERO,
            GoldilocksField::ZERO,
            GoldilocksField::ZERO,
            [GoldilocksField::ZERO; 4],
            [GoldilocksField::ZERO; 4],
        );
        for def in &program.defs {
            executor.process_var_def(def);
        }
        executor
    }))
    .map_err(|p| panic_message(&p))
}

// ---------- differential loop ----------

enum Outcome {
    Value,
    Overflow,
    DivZero,
    InvalidCast,
    InvalidSplitBits,
}

fn mismatch(seed: u64, program: &Program, detail: String) -> ! {
    panic!(
        "random op graph mismatch (seed {seed})\n  {detail}\n  \
         reproduce: PSY_VM_RANDOM_GRAPH_SEED={seed} cargo test -p psy_vm random_op_graphs_match_native_execution\n\
         --- program ---\n{}----------------",
        dump_program(program)
    );
}

fn check_seed(seed: u64) -> Outcome {
    let program = program_for_seed(seed);
    let expected = mirror_eval(&program);
    match expected {
        Ok(mirror) => match run_executor(&program) {
            Ok(executor) => {
                // A k256-crafted signature must verify to true — an
                // independent ground truth on top of the mirror match.
                if let Some(idx) = program.crafted_secp_index {
                    assert!(
                        executor.bools[idx],
                        "crafted secp256k1 signature must verify to true (seed {seed})\n{}",
                        dump_program(&program)
                    );
                }
                let diff = pools_diff(&mirror, &executor);
                if diff == "<pools equal>\n" {
                    Outcome::Value
                } else {
                    mismatch(seed, &program, format!("[pool divergence]\n{diff}"))
                }
            }
            Err(rejection) => mismatch(
                seed,
                &program,
                format!("[executor rejected a program the mirror accepts: {rejection}]"),
            ),
        },
        Err((def_index, class)) => {
            let Err(rejection) = run_executor(&program) else {
                mismatch(
                    seed,
                    &program,
                    format!("[executor accepted an invalid program: mirror errored {class:?} at def #{def_index}]"),
                )
            };
            match classify_rejection(&rejection) {
                Some(got) if got == class => match class {
                    MirrorErr::Overflow => Outcome::Overflow,
                    MirrorErr::DivZero => Outcome::DivZero,
                    MirrorErr::InvalidCast => Outcome::InvalidCast,
                    MirrorErr::InvalidSplitBits => Outcome::InvalidSplitBits,
                },
                other => mismatch(
                    seed,
                    &program,
                    format!(
                        "[rejection class mismatch at def #{def_index}: expected {class:?}, executor says {other:?} ({rejection})]"
                    ),
                ),
            }
        }
    }
}

#[test]
fn random_op_graphs_match_native_execution() {
    if let Ok(raw) = std::env::var("PSY_VM_RANDOM_GRAPH_SEED") {
        check_seed(raw.trim().parse().expect("PSY_VM_RANDOM_GRAPH_SEED must be a u64"));
        return;
    }
    let iters: u64 = std::env::var("PSY_VM_RANDOM_GRAPH_ITERS")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(10_000);
    let base = 0x5EED_2026_0923_u64;
    let (mut values, mut overflows, mut div_zeros, mut invalid_casts, mut invalid_split_bits) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    for i in 0..iters {
        match check_seed(base ^ i.wrapping_mul(0x9E37_79B9_7F4A_7C15)) {
            Outcome::Value => values += 1,
            Outcome::Overflow => overflows += 1,
            Outcome::DivZero => div_zeros += 1,
            Outcome::InvalidCast => invalid_casts += 1,
            Outcome::InvalidSplitBits => invalid_split_bits += 1,
        }
    }
    println!(
        "random op graph differential: {iters} seeds passed \
         ({values} values, {overflows} expected overflows, {div_zeros} expected div-by-zero rejections, {invalid_casts} expected invalid casts, {invalid_split_bits} expected invalid split-bits)"
    );
}

// ---------- VmExecutor differential (the IDE-preview executor) ----------

fn vm_context() -> ExecutionContext {
    ExecutionContext {
        user_id: 0,
        contract_id: 0,
        caller_contract_id: 0,
        checkpoint_id: 0,
        nonce: 0,
        user_public_key_hash: [0; 4],
        session_proof_tree_root: [0; 4],
    }
}

/// The third native executor (PsyIDE preview / simulate CLI) must agree
/// with the same mirror: accepted programs produce identical scalar
/// outputs in definition order; rejected programs fail with the same
/// rejection class (VmExecutor errors carry the semantics Display
/// strings, so the same classifier applies).
#[test]
fn random_op_graphs_match_vm_executor() {
    if let Ok(raw) = std::env::var("PSY_VM_RANDOM_GRAPH_SEED") {
        check_seed_vm_executor(raw.trim().parse().expect("seed must be a u64"));
        return;
    }
    let iters: u64 = std::env::var("PSY_VM_EXECUTOR_ITERS")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(10_000);
    let base = 0x5EED_2026_0923_u64;
    for i in 0..iters {
        check_seed_vm_executor(base ^ i.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    }
    println!("random op graph VmExecutor differential: {iters} seeds passed");
}

fn check_seed_vm_executor(seed: u64) {
    let program = program_for_seed(seed);
    let defn = program_definition(&program);
    let mut executor = VmExecutor::new(InMemoryStateBackend::new());

    match mirror_eval(&program) {
        Ok(mirror) => {
            let expected = expected_scalar_outputs(&mirror, &program);
            let result = executor
                .execute(&defn, &vm_context(), &program.input_values)
                .unwrap_or_else(|e| {
                    panic!("mirror-accepted program must execute (seed {seed}): {e}\n{}", dump_program(&program))
                });
            for (i, (got, want)) in result.outputs.iter().zip(&expected).enumerate() {
                assert_eq!(
                    got, want,
                    "VmExecutor output #{i} mismatch (seed {seed})\n{}",
                    dump_program(&program)
                );
            }
        }
        Err((def_index, class)) => {
            let err = match executor.execute(&defn, &vm_context(), &program.input_values) {
                Err(e) => e,
                Ok(_) => panic!(
                    "VmExecutor accepted a mirror-rejected program (seed {seed})\n{}",
                    dump_program(&program)
                ),
            };
            match classify_rejection(&err.to_string()) {
                Some(got) if got == class => {}
                other => panic!(
                    "rejection class mismatch (seed {seed}): mirror failed {class:?} at def #{def_index}, VmExecutor says {other:?} ({err})\n{}",
                    dump_program(&program)
                ),
            }
        }
    }
}

// ---------- core_eval differential (the pre-compilation evaluator) ----------

use super::fuzz_support::build_sym_store;
use crate::dpn::eval::traits::{ContextEval as _, ContextInput, EvalCache};
use crate::dpn::ops::sym_felt::SymFeltRef;

struct VecInput<'a> {
    values: &'a [u64],
}
impl ContextInput for VecInput<'_> {
    fn get_input(&self, index: u64) -> u64 {
        self.values[index as usize]
    }
    fn get_contract_id(&self) -> u64 {
        0
    }
    fn get_contract_deployer(&self, _contract_id: u64) -> [u64; 4] {
        [0; 4]
    }
    fn get_caller_contract_id(&self) -> u64 {
        0
    }
    fn get_user_id(&self) -> u64 {
        0
    }
    fn get_user_nonce(&self) -> u64 {
        0
    }
    fn get_checkpoint_id(&self) -> u64 {
        0
    }
    fn get_user_public_key_hash(&self) -> [u64; 4] {
        [0; 4]
    }
    fn get_session_proof_tree_root(&self) -> [u64; 4] {
        [0; 4]
    }
    fn get_self_current_contract_slot(&self, _index: u64) -> u64 {
        0
    }
    fn get_self_contract_slot(&self, _contract_id: u64, _index: u64) -> u64 {
        0
    }
    fn get_global_contract_slot(&self, _user_id: u64, _contract_id: u64, _index: u64) -> u64 {
        0
    }
}

#[derive(Default)]
struct HashMapCache {
    scalars: std::collections::HashMap<SymFeltRef, u64>,
    arrays: std::collections::HashMap<SymFeltRef, Vec<u64>>,
}
impl EvalCache for HashMapCache {
    fn contains(&self, key: SymFeltRef) -> bool {
        self.scalars.contains_key(&key)
    }
    fn get(&self, key: SymFeltRef) -> u64 {
        self.scalars[&key]
    }
    fn insert(&mut self, key: SymFeltRef, value: u64) {
        self.scalars.insert(key, value);
    }
    fn contains_arr(&self, key: SymFeltRef) -> bool {
        self.arrays.contains_key(&key)
    }
    fn get_arr_ref(&self, key: SymFeltRef) -> Box<Vec<u64>> {
        Box::new(self.arrays[&key].clone())
    }
    fn insert_arr(&mut self, key: SymFeltRef, value: Vec<u64>) {
        self.arrays.insert(key, value);
    }
}

/// The fourth evaluator: the pre-compilation `core_eval` over the reverse-
/// mapped SymFeltStore graph must agree with the same mirror - identical
/// scalar/array values on acceptance, identical rejection class and first
/// failing def on rejection.
#[test]
fn random_op_graphs_match_core_eval() {
    if let Ok(raw) = std::env::var("PSY_VM_RANDOM_GRAPH_SEED") {
        check_seed_core_eval(raw.trim().parse().expect("seed must be a u64"));
        return;
    }
    let iters: u64 = std::env::var("PSY_VM_CORE_EVAL_ITERS")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(10_000);
    let base = 0x5EED_2026_0923_u64;
    for i in 0..iters {
        check_seed_core_eval(base ^ i.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    }
    println!("random op graph core_eval differential: {iters} seeds passed");
}

fn check_seed_core_eval(seed: u64) {
    use crate::dpn::ops::op_types::DPNBuiltInDataType as Lane;

    let program = program_for_seed(seed);
    let sym = build_sym_store(&program);
    let input = VecInput { values: &program.input_values };
    let mirror = mirror_eval(&program);

    // Evaluate defs in order (core_eval is lazy/recursive; calling in def
    // order makes the first panicking def the first failing def, matching
    // the mirror's sequential semantics).
    let mut cache = HashMapCache::default();
    for (i, def) in program.defs.iter().enumerate() {
        let r = sym.refs[&(def.data_type, def.index)];
        let is_array = matches!(
            def.data_type,
            Lane::BoolArray | Lane::U32TargetArray | Lane::TargetArray | Lane::HashOut
        );
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if is_array {
                sym.store.resolve_array_ref_cached(r, &input, &mut cache).to_vec()
            } else {
                vec![sym.store.resolve_felt_ref_cached(r, &input, &mut cache)]
            }
        }));
        match (&mirror, outcome) {
            // On the accepted path every def must evaluate to the mirror
            // value (arrays flattened, hashes as their 4 elements).
            (Ok(m), Ok(vals)) => {
                let want: Vec<u64> = match def.data_type {
                    Lane::Target => vec![m.targets[def.index]],
                    Lane::U32Target => vec![m.u32s[def.index] as u64],
                    Lane::Bool => vec![m.bools[def.index] as u64],
                    Lane::BoolArray => m.bool_arrays[def.index].iter().map(|&b| b as u64).collect(),
                    Lane::U32TargetArray => m.u32_arrays[def.index].iter().map(|&w| w as u64).collect(),
                    Lane::TargetArray => m.target_arrays[def.index].clone(),
                    Lane::HashOut => m.hashes[def.index].to_vec(),
                    _ => unreachable!(),
                };
                assert_eq!(vals, want, "core_eval def #{i} mismatch (seed {seed})\n{}", dump_program(&program));
            }
            // On the rejected path the first panicking def must BE the
            // mirror's first failing def, with the same rejection class.
            (Err((fail_index, class)), Err(payload)) => {
                assert_eq!(
                    i, *fail_index,
                    "core_eval failed at def #{i}, mirror at def #{fail_index} (seed {seed})\n{}",
                    dump_program(&program)
                );
                let msg = panic_message(&payload);
                match classify_rejection(&msg) {
                    Some(got) if got == *class => {}
                    other => panic!(
                        "rejection class mismatch (seed {seed}) at def #{i}: mirror {class:?}, core_eval {other:?} ({msg})\n{}",
                        dump_program(&program)
                    ),
                }
                return;
            }
            (Ok(_), Err(payload)) => panic!(
                "core_eval rejected a mirror-accepted program at def #{i} (seed {seed}): {}\n{}",
                panic_message(&payload),
                dump_program(&program)
            ),
            // Before the mirror's failing def, evaluation must succeed
            // (the mirror drops its pool snapshot on failure, so values
            // are not compared here - the witness harness covers them).
            (Err((fail_index, _)), Ok(_)) if i < *fail_index => {}
            (Err((fail_index, class)), Ok(_)) => panic!(
                "core_eval accepted def #{i} but the mirror failed {class:?} at def #{fail_index} (seed {seed})\n{}",
                dump_program(&program)
            ),
        }
    }
    assert!(mirror.is_ok(), "mirror rejected but core_eval accepted everything (seed {seed})\n{}", dump_program(&program));
}

// ---------- compile-path fuzz (real producer -> compile_exec -> defs) ----------

/// Unlike the hand-built defs above (which MIMIC compile output), this
/// harness drives the real producer: random op_* calls on QExecContext
/// build a genuine SymFeltStore DAG, compile_exec lowers it through
/// injest_sfr, and the resulting definitions must (a) PASS the structural
/// validator and (b) execute identically on the witness and VmExecutor
/// against the same native mirror used everywhere else.
#[test]
fn random_compile_path_produces_valid_executable_defs() {
    use crate::dpn::ops::context_trait::DPNContext as _;
    use crate::dpn::ops::op_types::DPNOpType;
    use crate::dpn::ops::exec_context::QExecContext;
    use crate::dpn::ops::sym_felt::SymFeltRef;
    use crate::dpn::vm::compile::PsyCompileResult;
    use crate::dpn::vm::validate::validate_function_definition;

    let iters: u64 = std::env::var("PSY_VM_COMPILE_FUZZ_ITERS")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(2_000);
    let base = 0xC0FF_EE00_0000_0001_u64;

    for i in 0..iters {
        let seed = base ^ i.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let mut ctx = QExecContext::new();

        // A few positional inputs of mixed lanes.
        let mut rng = crate::dpn::vm::fuzz_support::Rng::new(seed);
        let n_inputs = 2 + (rng.next_u64() % 3) as u64;
        let mut inputs: Vec<SymFeltRef> = Vec::new();
        let mut input_values: Vec<u64> = Vec::new();
        for _ in 0..n_inputs {
            let roll = rng.next_u64() % 100;
            if roll < 50 {
                inputs.push(ctx.add_input());
                input_values.push(crate::dpn::vm::fuzz_support::felt_literal(&mut rng));
            } else if roll < 85 {
                inputs.push(ctx.add_u32_input());
                input_values.push(crate::dpn::vm::fuzz_support::u32_literal(&mut rng) as u64);
            } else {
                inputs.push(ctx.add_bool_input());
                input_values.push((rng.next_u64() & 1 == 0) as u64);
            }
        }

        // Chain random ops through the real producer across EVERY routable
        // opcode family, keeping a pool of live refs per lane so each op
        // can pick fresh operands.
        let mut felt_pool: Vec<SymFeltRef> = inputs
            .iter()
            .filter(|r| r.get_op_type() == DPNOpType::InputTarget)
            .copied()
            .collect();
        if felt_pool.is_empty() {
            felt_pool.push(ctx.op_const(5));
        }
        let mut u32_pool: Vec<SymFeltRef> = inputs
            .iter()
            .filter(|r| r.get_op_type() == DPNOpType::U32InputTarget)
            .copied()
            .collect();
        if u32_pool.is_empty() {
            u32_pool.push(ctx.op_const_u32(9));
        }
        let mut bool_pool: Vec<SymFeltRef> = vec![ctx.op_true()];

        let pick_felt = |rng: &mut crate::dpn::vm::fuzz_support::Rng, p: &Vec<SymFeltRef>| -> SymFeltRef {
            p[(rng.next_u64() % p.len() as u64) as usize]
        };

        let n_ops = 10 + (rng.next_u64() % 20) as usize;
        let mut assertions = 0usize;
        let mut events = 0usize;
        for _ in 0..n_ops {
            let roll = rng.next_u64() % 100;
            if roll < 30 {
                // felt lane arithmetic + comparisons + casts
                let a = pick_felt(&mut rng, &felt_pool);
                let b = pick_felt(&mut rng, &felt_pool);
                // Pre-build every constant operand before the call (no
                // nested &mut ctx borrows in argument position).
                let c1 = ctx.op_const(1);
                let c3 = ctx.op_const(3);
                let c5 = ctx.op_const(5);
                let c7 = ctx.op_const(7);
                let r = match rng.next_u64() % 12 {
                    0 => ctx.op_add(a, b),
                    1 => ctx.op_mul(a, b),
                    2 => {
                        // op_sub on two ConstantU32 refs routes to the
                        // producer's checked U32Sub folding and can
                        // overflow-assert; the field identity a + (-b) is
                        // rejection-free.
                        let nb = ctx.op_neg(b);
                        ctx.op_add(a, nb)
                    }
                    3 => ctx.op_div(a, c7),
                    4 => ctx.op_mod(a, c3),
                    5 => ctx.op_exp(a, c5),
                    6 => ctx.op_exp(c3, b), // ExpConstantBase routing
                    7 => ctx.op_neg(a),
                    8 => ctx.op_div(c1, c7), // UnaryInverse of constant 7, never rejects
                    9 => ctx.op_lt(a, b),
                    _ => ctx.op_eq(a, b),
                };
                felt_pool.push(r);
            } else if roll < 55 {
                // u32 lane: arithmetic, bitwise (+constant routing), shifts
                let a = u32_pool[(rng.next_u64() % u32_pool.len() as u64) as usize];
                let a2 = u32_pool[(rng.next_u64() % u32_pool.len() as u64) as usize];
                let c1u = ctx.op_const_u32(1);
                let c2u = ctx.op_const_u32(2);
                let c3u = ctx.op_const_u32(3);
                let c5u = ctx.op_const_u32(5);
                let c7u = ctx.op_const_u32(7);
                let cand = ctx.op_const_u32(0x0f0f);
                let cor = ctx.op_const_u32(0xf0f0);
                let r = match rng.next_u64() % 12 {
                    // Checked u32 arithmetic rejects on overflow, so
                    // runtime-value ops stick to the overflow-free families
                    // (bitwise/shifts truncate; div/mod use nonzero
                    // constants). The rejecting paths are already fuzzed
                    // by the four differential harnesses; constant folding
                    // below covers the arithmetic producers' routing.
                    0 => ctx.op_u32_and(a, cand), // U32AndConstant routing
                    1 => ctx.op_u32_or(a, cor),
                    2 => ctx.op_u32_xor(a, a2),
                    3 => ctx.op_u32_shl(a, c3u), // ConstantValue routing
                    4 => ctx.op_u32_shr(a, c2u),
                    5 => ctx.op_u32_div(a, c7u),
                    6 => ctx.op_u32_mod(a, c5u),
                    7 => ctx.op_u32_and(a, a2),
                    8 => {
                        let base = ctx.op_const_u32(3);
                        ctx.op_u32_exp(base, c2u) // 3^2, checked-safe
                    }
                    9 => ctx.op_u32_or(a, a2),
                    _ => ctx.op_u32_xor(a, cand),
                };
                u32_pool.push(r);
            } else if roll < 70 {
                // boolean lane
                let a = bool_pool[(rng.next_u64() % bool_pool.len() as u64) as usize];
                let b = bool_pool[(rng.next_u64() % bool_pool.len() as u64) as usize];
                let r = match rng.next_u64() % 6 {
                    0 => ctx.op_bool_and(a, b),
                    1 => ctx.op_bool_or(a, b),
                    2 => ctx.op_bool_xor(a, b),
                    3 => ctx.op_bool_not(a),
                    _ => ctx.op_lt(
                        felt_pool[(rng.next_u64() % felt_pool.len() as u64) as usize],
                        felt_pool[(rng.next_u64() % felt_pool.len() as u64) as usize],
                    ),
                };
                bool_pool.push(r);
            } else if roll < 78 {
                // casts + select
                let r = match rng.next_u64() % 4 {
                    0 => ctx.op_cast_u32(u32_pool[0]),
                    1 => ctx.op_cast_felt(felt_pool[0]),
                    2 => ctx.op_cast_bool(bool_pool[0]),
                    _ => {
                        let cond = bool_pool[(rng.next_u64() % bool_pool.len() as u64) as usize];
                        let t = pick_felt(&mut rng, &felt_pool);
                        let f = pick_felt(&mut rng, &felt_pool);
                        ctx.op_select(cond, t, f)
                    }
                };
                felt_pool.push(r);
            } else if roll < 86 {
                // hash lane: poseidon + keccak + split_bits/sum_bits roundtrip
                let r = match rng.next_u64() % 4 {
                    0 => {
                        let vals: Vec<SymFeltRef> =
                            (0..1 + rng.next_u64() % 4).map(|_| pick_felt(&mut rng, &felt_pool)).collect();
                        ctx.hash(&vals)[0]
                    }
                    1 => {
                        // keccak words must be u32-lane values (cast_u32 of
                        // an arbitrary felt rejects, correctly).
                        let words: Vec<SymFeltRef> = (0..1 + rng.next_u64() % 4)
                            .map(|_| u32_pool[(rng.next_u64() % u32_pool.len() as u64) as usize])
                            .collect();
                        ctx.keccak256(&words)[0]
                    }
                    2 => {
                        // split_bits value must fit num_bits - use a small
                        // constant (the rejection path is covered by the
                        // hand-built harnesses).
                        let v = ctx.op_const(rng.next_u64() % 256);
                        let bits = ctx.split_bits(v, 8);
                        ctx.sum_bits(&bits)
                    }
                    _ => {
                        let l = ctx.hash(&[pick_felt(&mut rng, &felt_pool)]);
                        let r = ctx.hash(&[pick_felt(&mut rng, &felt_pool)]);
                        ctx.hash_two_to_one(&l, &r)[0]
                    }
                };
                felt_pool.push(r);
            } else if roll < 92 {
                // constant folding: both-constant ops fold at the producer
                let k7 = ctx.op_const(7);
                let k5 = ctx.op_const(5);
                let k100 = ctx.op_const(100);
                let k7u = ctx.op_const_u32(7);
                let k6u = ctx.op_const_u32(6);
                let r = match rng.next_u64() % 3 {
                    0 => ctx.op_add(k7, k5),
                    1 => ctx.op_u32_mul(k7u, k6u),
                    _ => ctx.op_mod(k100, k7),
                };
                felt_pool.push(r);
            } else if roll < 96 {
                // assertions on live values
                let a = pick_felt(&mut rng, &felt_pool);
                let b = pick_felt(&mut rng, &felt_pool);
                if assertions < 4 {
                    ctx.assert_eq(a, b, "compile-fuzz assert");
                    assertions += 1;
                }
            } else {
                // events with live data
                if events < 3 {
                    let data: Vec<SymFeltRef> =
                        (0..1 + rng.next_u64() % 3).map(|_| pick_felt(&mut rng, &felt_pool)).collect();
                    ctx.emit_event(data);
                    events += 1;
                }
            }
        }

        // Multiple outputs across lanes.
        let mut outputs = vec![*felt_pool.last().unwrap()];
        if let Some(u) = u32_pool.last() {
            outputs.push(ctx.op_cast_felt(*u));
        }
        if let Some(b) = bool_pool.last() {
            if b.get_op_type() != DPNOpType::ConstantTrue {
                outputs.push(ctx.op_cast_felt(*b));
            }
        }

        // Lower through the REAL compile path.
        let defn = PsyCompileResult::compile_exec(
            "compile-fuzz".to_string(),
            0,
            &ctx.store,
            &ctx,
            &outputs,
        );

        // (a) The structural validator must accept real compiler output.
        if let Err(e) = validate_function_definition(&defn) {
            panic!("compile_exec output failed validation (seed {seed}): {e}");
        }

        // (b) Cross-check two INDEPENDENT executors on the real compiled
        // defs: witness vs VmExecutor (arithmetic semantics themselves are
        // already pinned by the four differential harnesses; the oracle
        // here is producer+compiler+validator path integrity).
        let vm = {
            let ctx = crate::dpn::eval::executor::ExecutionContext {
                user_id: 0,
                contract_id: 0,
                caller_contract_id: 0,
                checkpoint_id: 0,
                nonce: 0,
                user_public_key_hash: [0; 4],
                session_proof_tree_root: [0; 4],
            };
            let mut ex = VmExecutor::new(InMemoryStateBackend::new());
            let r = ex.execute(&defn, &ctx, &input_values).unwrap_or_else(|e| {
                panic!("VmExecutor rejected compile-path program (seed {seed}): {e}")
            });
            r.outputs
        };
        let mut executor = SimpleDPNExecutor::<GoldilocksField>::new_with_contract_ctx(
            input_values.iter().map(|v| GoldilocksField::from_noncanonical_u64(*v)).collect(),
            GoldilocksField::ZERO,
            GoldilocksField::ZERO,
            GoldilocksField::ZERO,
            GoldilocksField::ZERO,
            GoldilocksField::ZERO,
            [GoldilocksField::ZERO; 4],
            [GoldilocksField::ZERO; 4],
        );
        for def in &defn.definitions {
            executor.process_var_def(def);
        }
        for (i, (&out, want)) in defn.circuit_outputs.iter().zip(&vm).enumerate() {
            let got = executor.resolve_target(out).to_canonical_u64();
            assert_eq!(
                got, *want,
                "compile-path witness vs VmExecutor mismatch at output {i} (seed {seed})"
            );
        }
    }
    println!("random compile-path fuzz: {iters} programs compiled, validated and executed");
}

// ---------- validator negative-mutation fuzz ----------

/// The structural validator is the gate every executor trusts; this
/// harness mutates VALID generated programs structurally and requires the
/// validator to REJECT each mutant - a validator that silently accepts a
/// malformed definition is worse than one that panics. Mutations map to
/// the specific ValidationError kinds they must trigger.
#[test]
fn random_mutations_are_rejected_by_validator() {
    use crate::dpn::ops::op_types::DPNBuiltInDataType;
    use crate::dpn::ops::op_types::DPNOpType;
    use crate::dpn::vm::fuzz_support::{mirror_eval, program_definition, program_for_seed};
    use crate::dpn::vm::validate::{validate_function_definition, ValidationError};

    let iters: u64 = std::env::var("PSY_VM_MUTATION_FUZZ_ITERS")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(2_000);
    let base = 0xAD_BAD_BAD_0000_0001_u64;
    let (mut rejections, mut by_kind) = (0u64, std::collections::BTreeMap::new());

    for i in 0..iters {
        let seed = base ^ i.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        // Pick a mirror-ACCEPTED program (mutation targets are valid).
        let program = loop {
            let p = program_for_seed(seed ^ (i << 32) ^ rejections);
            if mirror_eval(&p).is_ok() {
                break p;
            }
            rejections += 1; // advance the probe until accepted
        };
        let mut defn = program_definition(&program);
        let mut rng = crate::dpn::vm::fuzz_support::Rng::new(seed);

        // One structural mutation per mutant.
        let n_defs = defn.definitions.len();
        let di = (rng.next_u64() % n_defs.max(1) as u64) as usize;
        let mutation_id = rng.next_u64() % 12;
        let expect: Option<&'static str> = match mutation_id {
            0 => {
                // Wrong arity: truncate/extend inputs of a fixed-arity op.
                // Valueless getters accept 0..=1 inputs, so mutate only
                // ops with a real operand list.
                let fixed_arity = !matches!(
                    defn.definitions[di].op_type,
                    DPNOpType::Constant | DPNOpType::ConstantU32 | DPNOpType::ConstantTrue
                        | DPNOpType::ConstantFalse | DPNOpType::InputTarget
                        | DPNOpType::U32InputTarget | DPNOpType::BoolInputTarget
                        | DPNOpType::GetUserId | DPNOpType::GetContractId
                        | DPNOpType::GetCallerContractId | DPNOpType::GetCheckpointId
                        | DPNOpType::GetNonce | DPNOpType::GetUserPublicKeyHash
                        | DPNOpType::GetSessionProofTreeRoot
                        | DPNOpType::Keccak256 | DPNOpType::HashNoPad // variadic
                        | DPNOpType::SumBits // variadic up to 64
                        | DPNOpType::GetStateCommandResultHash
                        | DPNOpType::GetStateCommandResultSingle
                        | DPNOpType::GetStateCommandResultArray
                );
                if fixed_arity {
                    if defn.definitions[di].inputs.len() > 1 {
                        defn.definitions[di].inputs.truncate(1);
                    } else {
                        defn.definitions[di].inputs.push(0);
                        defn.definitions[di].inputs.push(0);
                    }
                    Some("BadArity")
                } else {
                    defn.definitions[di].index += 1;
                    Some("BadPoolIndex")
                }
            }
            1 => {
                // Forward reference: point slot 0 at a far-future index.
                // Only meaningful on defs whose inputs are operand ids
                // (constants carry raw values; getters carry none).
                let inline = matches!(
                    defn.definitions[di].op_type,
                    DPNOpType::Constant
                        | DPNOpType::ConstantU32
                        | DPNOpType::ConstantTrue
                        | DPNOpType::ConstantFalse
                        | DPNOpType::InputTarget
                        | DPNOpType::U32InputTarget
                        | DPNOpType::BoolInputTarget
                        | DPNOpType::GetUserId
                        | DPNOpType::GetContractId
                        | DPNOpType::GetCallerContractId
                        | DPNOpType::GetCheckpointId
                        | DPNOpType::GetNonce
                        | DPNOpType::GetUserPublicKeyHash
                        | DPNOpType::GetSessionProofTreeRoot
                );
                if inline || defn.definitions[di].inputs.is_empty() {
                    defn.definitions[di].index += 1;
                    Some("BadPoolIndex")
                } else {
                    let lane = defn.definitions[di].data_type;
                    defn.definitions[di].inputs[0] =
                        crate::dpn::ops::op_types::encode_indexed_op_id(lane, n_defs + 5);
                    Some("BadOperand")
                }
            }
            2 => {
                // Pool index gap: bump the def's own index.
                defn.definitions[di].index += 1;
                Some("BadPoolIndex")
            }
            3 => {
                // Data-type/lane mismatch.
                defn.definitions[di].data_type = match defn.definitions[di].data_type {
                    DPNBuiltInDataType::Target => DPNBuiltInDataType::Bool,
                    _ => DPNBuiltInDataType::Target,
                };
                Some("BadDataType")
            }
            4 => {
                // Out-of-range constant.
                if defn.definitions[di].op_type == DPNOpType::ConstantU32 {
                    defn.definitions[di].inputs[0] = 0x1_0000_0000;
                    Some("BadConstant")
                } else if defn.definitions[di].op_type == DPNOpType::Constant {
                    defn.definitions[di].inputs[0] = 0xffff_ffff_0000_0001; // >= p
                    Some("BadConstant")
                } else {
                    // Pick a def that is actually a constant to corrupt;
                    // otherwise the mutation may be a no-op on this def.
                    let target = defn
                        .definitions
                        .iter()
                        .position(|d| d.op_type == DPNOpType::Constant || d.op_type == DPNOpType::ConstantU32);
                    match target {
                        Some(t) => {
                            let v = if defn.definitions[t].op_type == DPNOpType::ConstantU32 {
                                0x1_0000_0000
                            } else {
                                0xffff_ffff_0000_0001
                            };
                            defn.definitions[t].inputs[0] = v;
                        }
                        None => {
                            defn.definitions[di].inputs.push(0);
                            defn.definitions[di].inputs.push(0);
                        }
                    }
                    Some("BadConstant")
                }
            }
            5 => {
                // Input def: out-of-range positional index.
                defn.definitions[di].op_type = DPNOpType::InputTarget;
                defn.definitions[di].data_type = DPNBuiltInDataType::Target;
                defn.definitions[di].inputs = vec![defn.circuit_inputs.len() as u64 + 9];
                Some("BadInputIndex")
            }
            6 => {
                // SplitBits with num_bits > 64.
                defn.definitions[di].op_type = DPNOpType::SplitBits;
                defn.definitions[di].data_type = DPNBuiltInDataType::BoolArray;
                defn.definitions[di].index = 0;
                defn.definitions[di].inputs = vec![65, 0, 0];
                Some("BadSplitBitsNumBits")
            }
            7 => {
                // Dangling circuit output.
                defn.circuit_outputs.push(
                    crate::dpn::ops::op_types::encode_indexed_op_id(DPNBuiltInDataType::Target, n_defs + 99),
                );
                Some("BadOutputId")
            }
            8 => {
                // State-command result with no state commands.
                defn.definitions[di].op_type = DPNOpType::GetStateCommandResultSingle;
                defn.definitions[di].data_type = DPNBuiltInDataType::Target;
                defn.definitions[di].inputs = vec![0];
                Some("BadStateCommandRef")
            }
            9 => {
                // Resolution indices mismatched with state commands.
                defn.state_command_resolution_indices = vec![1];
                Some("BadResolutionIndices")
            }
            10 => {
                // Unsupported opcode injection.
                defn.definitions[di].op_type = DPNOpType::HashPad;
                Some("UnsupportedOpcode")
            }
            _ => {
                // More events than the per-call maximum (32).
                use crate::dpn::ops::op_types::DPNEventRecord;
                defn.events = (0..33)
                    .map(|_| DPNEventRecord {
                        condition: 0,
                        checkpoint_id: 0,
                        user_id: 0,
                        contract_id: 0,
                        data: vec![],
                    })
                    .collect();
                Some("TooManyEvents")
            }
        };

        match validate_function_definition(&defn) {
            Err(e) => {
                let kind = match e {
                    ValidationError::UnsupportedOpcode { .. } => "UnsupportedOpcode",
                    ValidationError::BadArity { .. } => "BadArity",
                    ValidationError::BadDataType { .. } => "BadDataType",
                    ValidationError::BadPoolIndex { .. } => "BadPoolIndex",
                    ValidationError::BadOperand { .. } | ValidationError::OperandLane { .. } => "BadOperand/Lane",
                    ValidationError::BadConstant { .. } => "BadConstant",
                    ValidationError::BadInputIndex { .. } => "BadInputIndex",
                    ValidationError::InputsNotFirst { .. } => "InputsNotFirst",
                    ValidationError::BadSplitBitsNumBits { .. } => "BadSplitBitsNumBits",
                    ValidationError::BadStateCommandRef { .. } => "BadStateCommandRef",
                    ValidationError::ConstantPosition { .. } => "ConstantPosition",
                    ValidationError::BadResolutionIndices => "BadResolutionIndices",
                    ValidationError::BadOutputId { .. } => "BadOutputId",
                    ValidationError::TooManyEvents { .. } => "TooManyEvents",
                };
                // The mutation must not be silently accepted; the exact
                // kind may differ when a mutation lands on an
                // earlier-checked def property, but the program must be
                // REJECTED.
                let _ = expect;
                *by_kind.entry(kind.to_string()).or_insert(0u64) += 1;
                rejections += 1;
            }
            Ok(()) => panic!(
                "validator ACCEPTED a mutated program (seed {seed}, mutation #{mutation_id} at def #{di}: {:?} lane={:?} idx={} inputs={:?})\n{}",
                defn.definitions[di].op_type,
                defn.definitions[di].data_type,
                defn.definitions[di].index,
                defn.definitions[di].inputs,
                crate::dpn::vm::fuzz_support::dump_program(&program)
            ),
        }
    }
    println!("validator mutation fuzz: {iters} mutants all rejected: {by_kind:?}");
}
