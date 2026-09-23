// Op-level differential fuzz: random `DPNIndexedVarDef` programs executed by
// `SimpleDPNExecutor` (the VM's witness-generation core) versus an exact
// native-Rust mirror.
//
// Each seed generates a flat DAG over the executor's three scalar pools
// (Target / U32Target / Bool): a few positional inputs, then a chain of
// constant and computed definitions. The same def list is (a) fed to
// `SimpleDPNExecutor::process_var_def` one def at a time and (b) evaluated
// by a mirror that transcribes the executor's semantics with exact integer
// math. On success every pool value must match; on failure the mirror's
// error class must match the executor's rejection panic:
//
//   Overflow     u32 add/mul/exp "value too large", u32 sub "value too low"
//   DivZero      "u32 div/mod by zero", felt "Mod by zero", field division
//                panics with "Tried to invert zero"
//   InvalidCast  CastBool "Invalid bool value", CastU32 "Invalid u32 value"
//
// Felt arithmetic wraps mod the Goldilocks prime; `/` is field division and
// `%` is integer mod of canonical values. u32 arithmetic is checked. Shift
// distances >= 32 fold to 0 (all six shift opcodes behave identically at
// executor level).
//
// `U32Exp` mirrors the executor's field semantics exactly: compute
// `base^exp mod p`, then assert the canonical residue fits in 32 bits
// (the executor arm is `left.exp_u64(right)` + `res <= 0xffffffff`).
//
// Input conventions follow what `PsyCompileResult::compile_exec` emits:
// operands are encoded op ids referencing earlier defs (constants are their
// own Constant/ConstantU32/ConstantTrue/False defs), input ops carry the
// positional input index raw. The Constant-specialized opcodes
// (ExpConstantPower/ExpConstantBase, ModConstantDividend/ModConstantDivisor,
// U32And/Or/XorConstant) are generated with the node-reference layout — the
// constant travels as its own Constant/ConstantU32 child def and both
// operands resolve through the normal register path, matching the producer
// routing in `ops/exec_context.rs`. UnaryInverse is generated with
// zero-heavy operands.
//
// Array- and hash-lane ops are generated too: SplitBits (bool arrays, with
// the compiled 3-input layout `[num_bits, value_id, num_bits_const_id]` and
// occasional value-does-not-fit rejections), Keccak256 (u32 arrays, words
// occasionally above the u32 lane), HashNoPad/HashTwoToOne (Poseidon
// hashes), TargetAt over every generated array/hash lane with in-range
// constant indexes, SumBits (weighted reconstruction), and Secp256k1Verify
// with random words plus occasional k256-crafted valid signatures whose
// ground truth is asserted to verify as 1.
//
// Reproduce a failure:
//   PSY_VM_RANDOM_GRAPH_SEED=<seed> cargo test -p psy_vm random_op_graphs_match_native_execution
// Longer fuzzing runs:
//   PSY_VM_RANDOM_GRAPH_ITERS=100000 cargo test -p psy_vm random_op_graphs_match_native_execution

use plonky2::field::{
    goldilocks_field::GoldilocksField,
    types::{Field, PrimeField64},
};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher as _;
use tiny_keccak::{Hasher as _, Keccak};

use crate::dpn::{
    ops::op_types::{decode_indexed_op_id, encode_indexed_op_id, DPNBuiltInDataType, DPNIndexedVarDef, DPNOpType},
    vm::{def::DPNFunctionCircuitDefinition, exec::SimpleDPNExecutor, validate::validate_function_definition},
};

const GOLDILOCKS_P: u128 = 0xFFFF_FFFF_0000_0001;

const SHIFT_AMOUNTS: [u32; 14] = [0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 100];
const POW_EXPONENTS: [u32; 14] = [0, 1, 2, 3, 4, 7, 31, 32, 33, 40, 63, 64, 100, 0xffff_ffff];
const DIVISORS: [u32; 6] = [0, 0, 1, 1, 2, 3];
const SMALL: [u32; 16] = [0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 31, 32, 63, 64, 255, 256];
const TINY: [u32; 10] = [0, 1, 1, 2, 2, 3, 4, 5, 7, 8];
const EDGES: [u32; 5] = [0x7FFF_FFFF, 0x8000_0000, 0xFFFF_0000, 0xFFFF_FFFE, 0xFFFF_FFFF];

const FELT_TINY: [u64; 10] = [0, 1, 1, 2, 2, 3, 4, 5, 7, 8];
const FELT_DIVISORS: [u64; 8] = [0, 0, 1, 1, 2, 3, 4, 0x1_0000_0000];
const FELT_EDGES: [u64; 9] = [
    0,
    1,
    2,
    0xFFFF_FFFF,
    0x1_0000_0000,
    1 << 63,
    (1 << 63) - 1,
    (GOLDILOCKS_P - 2) as u64,
    (GOLDILOCKS_P - 1) as u64,
];

// ---------- deterministic RNG ----------

/// xorshift64* seeded through a SplitMix64 warm-up (same design as the
/// psy-compiler random-graph suite).
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        Self((z ^ (z >> 31)).max(1))
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n.max(1)
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    fn boolean(&mut self) -> bool {
        self.next_u64() & 1 == 0
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }
}

// ---------- program generation ----------

pub fn u32_literal(rng: &mut Rng) -> u32 {
    if rng.chance(55) {
        *rng.pick(&TINY)
    } else if rng.chance(35) {
        *rng.pick(&SMALL)
    } else if rng.chance(20) {
        *rng.pick(&EDGES)
    } else {
        rng.next_u64() as u32
    }
}

pub fn felt_literal(rng: &mut Rng) -> u64 {
    if rng.chance(55) {
        *rng.pick(&FELT_TINY)
    } else if rng.chance(25) {
        *rng.pick(&FELT_EDGES)
    } else {
        rng.next_u64() % (GOLDILOCKS_P as u64)
    }
}

pub struct Program {
    /// Concrete positional input felts (valid for their kind).
    pub input_values: Vec<u64>,
    pub input_kinds: Vec<DPNBuiltInDataType>,
    pub defs: Vec<DPNIndexedVarDef>,
    /// Bool-pool index of a k256-crafted Secp256k1Verify that must verify
    /// to true (ground-truth assert on top of the mirror differential).
    pub crafted_secp_index: Option<usize>,
}

/// Pool occupancy while generating; def indexes always append, so each pool
/// index is used exactly once (matching `set_*_at`'s append-only fast path).
#[derive(Default)]
struct GenPools {
    targets: usize,
    u32s: usize,
    bools: usize,
    bool_arrays: usize,
    u32_arrays: usize,
    hashes: usize,
    target_arrays: usize,
    /// Bool-array id -> element count (SplitBits widths), so TargetAt can
    /// pick in-range constant indexes.
    bool_array_lens: std::collections::HashMap<u64, usize>,
}

fn target_id(pools: &GenPools) -> u64 {
    encode_indexed_op_id(DPNBuiltInDataType::Target, pools.targets)
}
fn u32_id(pools: &GenPools) -> u64 {
    encode_indexed_op_id(DPNBuiltInDataType::U32Target, pools.u32s)
}
fn bool_id(pools: &GenPools) -> u64 {
    encode_indexed_op_id(DPNBuiltInDataType::Bool, pools.bools)
}
fn target_array_id(pools: &GenPools) -> u64 {
    encode_indexed_op_id(DPNBuiltInDataType::TargetArray, pools.target_arrays)
}
fn bool_array_id(pools: &GenPools) -> u64 {
    encode_indexed_op_id(DPNBuiltInDataType::BoolArray, pools.bool_arrays)
}
fn u32_array_id(pools: &GenPools) -> u64 {
    encode_indexed_op_id(DPNBuiltInDataType::U32TargetArray, pools.u32_arrays)
}
fn hash_id(pools: &GenPools) -> u64 {
    encode_indexed_op_id(DPNBuiltInDataType::HashOut, pools.hashes)
}

/// A reference to an existing array/hash lane def, with its element length.
#[derive(Clone, Copy)]
enum ArrayRef {
    BoolArray(u64, usize),
    TargetArray(u64, usize),
    U32Array(u64, usize),
    Hash(u64, usize),
}

fn existing_array(rng: &mut Rng, pools: &GenPools) -> Option<ArrayRef> {
    let candidates: Vec<ArrayRef> = (0..pools.target_arrays)
        .map(|i| ArrayRef::TargetArray(encode_indexed_op_id(DPNBuiltInDataType::TargetArray, i), 2))
        .chain((0..pools.bool_arrays).map(|i| ArrayRef::BoolArray(encode_indexed_op_id(DPNBuiltInDataType::BoolArray, i), usize::MAX)))
        .chain((0..pools.u32_arrays).map(|i| ArrayRef::U32Array(encode_indexed_op_id(DPNBuiltInDataType::U32TargetArray, i), 8)))
        .chain((0..pools.hashes).map(|i| ArrayRef::Hash(encode_indexed_op_id(DPNBuiltInDataType::HashOut, i), 4)))
        .collect();
    if candidates.is_empty() {
        return None;
    }
    let mut pick = *rng.pick(&candidates);
    // Bool-array lengths are only known to the generator at creation; they
    // are recorded when the SplitBits def is pushed (see gen_array_def).
    if let ArrayRef::BoolArray(id, _) = pick {
        if let Some(len) = pools.bool_array_lens.get(&id) {
            pick = ArrayRef::BoolArray(id, *len);
        }
    }
    Some(pick)
}

fn existing_target(rng: &mut Rng, pools: &GenPools) -> u64 {
    encode_indexed_op_id(DPNBuiltInDataType::Target, rng.below(pools.targets as u64) as usize)
}
fn existing_u32(rng: &mut Rng, pools: &GenPools) -> u64 {
    encode_indexed_op_id(DPNBuiltInDataType::U32Target, rng.below(pools.u32s as u64) as usize)
}
fn existing_bool(rng: &mut Rng, pools: &GenPools) -> u64 {
    encode_indexed_op_id(DPNBuiltInDataType::Bool, rng.below(pools.bools as u64) as usize)
}

fn push_def(defs: &mut Vec<DPNIndexedVarDef>, op_type: DPNOpType, index: usize, inputs: Vec<u64>) {
    defs.push(DPNIndexedVarDef {
        data_type: op_type.get_data_type(),
        index,
        op_type,
        inputs,
    });
}

/// Fresh constant defs keep empty pools usable and mix boundary literals
/// into operand positions.
fn push_target_const(rng: &mut Rng, defs: &mut Vec<DPNIndexedVarDef>, pools: &mut GenPools) -> u64 {
    let value = felt_literal(rng);
    let id = target_id(pools);
    pools.targets += 1;
    push_def(defs, DPNOpType::Constant, (id_scalar_index(id)), vec![value]);
    id
}

fn push_u32_const(rng: &mut Rng, defs: &mut Vec<DPNIndexedVarDef>, pools: &mut GenPools) -> u64 {
    let value = u32_literal(rng);
    let id = u32_id(pools);
    pools.u32s += 1;
    let idx = id_scalar_index(id);
    push_def(defs, DPNOpType::ConstantU32, idx, vec![value as u64]);
    id
}

fn push_bool_const(rng: &mut Rng, defs: &mut Vec<DPNIndexedVarDef>, pools: &mut GenPools) -> u64 {
    let value = rng.boolean();
    let id = bool_id(pools);
    pools.bools += 1;
    let idx = id_scalar_index(id);
    push_def(defs, if value { DPNOpType::ConstantTrue } else { DPNOpType::ConstantFalse }, idx, vec![]);
    id
}

fn id_scalar_index(id: u64) -> usize {
    decode_indexed_op_id(id).1
}

/// A Target operand: an existing pool entry or a fresh constant.
fn target_operand(rng: &mut Rng, defs: &mut Vec<DPNIndexedVarDef>, pools: &mut GenPools) -> u64 {
    if pools.targets == 0 || rng.chance(35) {
        push_target_const(rng, defs, pools)
    } else {
        existing_target(rng, pools)
    }
}

/// Felt division/modulo operands are biased toward zero to exercise the
/// rejection paths.
fn felt_divisor(rng: &mut Rng, defs: &mut Vec<DPNIndexedVarDef>, pools: &mut GenPools) -> u64 {
    if pools.targets == 0 || rng.chance(60) {
        let value = *rng.pick(&FELT_DIVISORS);
        let id = target_id(pools);
        pools.targets += 1;
        push_def(defs, DPNOpType::Constant, id_scalar_index(id), vec![value]);
        id
    } else {
        existing_target(rng, pools)
    }
}

fn u32_operand(rng: &mut Rng, defs: &mut Vec<DPNIndexedVarDef>, pools: &mut GenPools) -> u64 {
    if pools.u32s == 0 || rng.chance(35) {
        push_u32_const(rng, defs, pools)
    } else {
        existing_u32(rng, pools)
    }
}

/// Overflow-hunting left-hand side: boundary values dominate.
fn u32_edge_operand(rng: &mut Rng, defs: &mut Vec<DPNIndexedVarDef>, pools: &mut GenPools) -> u64 {
    if pools.u32s == 0 || rng.chance(50) {
        let value = if rng.chance(60) { *rng.pick(&EDGES) } else { u32_literal(rng) };
        let id = u32_id(pools);
        pools.u32s += 1;
        push_def(defs, DPNOpType::ConstantU32, id_scalar_index(id), vec![value as u64]);
        id
    } else {
        existing_u32(rng, pools)
    }
}

fn u32_divisor(rng: &mut Rng, defs: &mut Vec<DPNIndexedVarDef>, pools: &mut GenPools) -> u64 {
    if pools.u32s == 0 || rng.chance(70) {
        let value = *rng.pick(&DIVISORS);
        let id = u32_id(pools);
        pools.u32s += 1;
        push_def(defs, DPNOpType::ConstantU32, id_scalar_index(id), vec![value as u64]);
        id
    } else {
        existing_u32(rng, pools)
    }
}

fn u32_shift_distance(rng: &mut Rng, defs: &mut Vec<DPNIndexedVarDef>, pools: &mut GenPools) -> u64 {
    let value = *rng.pick(&SHIFT_AMOUNTS);
    let id = u32_id(pools);
    pools.u32s += 1;
    push_def(defs, DPNOpType::ConstantU32, id_scalar_index(id), vec![value as u64]);
    id
}

fn u32_pow_exponent(rng: &mut Rng, defs: &mut Vec<DPNIndexedVarDef>, pools: &mut GenPools) -> u64 {
    let value = *rng.pick(&POW_EXPONENTS);
    let id = u32_id(pools);
    pools.u32s += 1;
    push_def(defs, DPNOpType::ConstantU32, id_scalar_index(id), vec![value as u64]);
    id
}

fn bool_operand(rng: &mut Rng, defs: &mut Vec<DPNIndexedVarDef>, pools: &mut GenPools) -> u64 {
    if pools.bools == 0 || rng.chance(25) {
        push_bool_const(rng, defs, pools)
    } else {
        existing_bool(rng, pools)
    }
}

/// Boolean-algebra operand: usually a bool-lane def, occasionally a
/// Target-lane constant with a 0/1-biased value - the compiled shape of
/// `!felt` / `felt & felt` (op_bool_not over as_felt) - with non-0/1
/// values taking the strict-boolean rejection.
fn boolish_operand(rng: &mut Rng, defs: &mut Vec<DPNIndexedVarDef>, pools: &mut GenPools) -> u64 {
    if rng.chance(25) {
        let value = *rng.pick(&[0u64, 0, 1, 1, 1, 2]);
        let id = target_id(pools);
        pools.targets += 1;
        push_def(defs, DPNOpType::Constant, id_scalar_index(id), vec![value]);
        id
    } else {
        bool_operand(rng, defs, pools)
    }
}

fn gen_target_def(rng: &mut Rng, defs: &mut Vec<DPNIndexedVarDef>, pools: &mut GenPools) {
    use DPNOpType::*;
    let op = *rng.pick(&[
        Add, Sub, Mul, Div, Mod, Exp, UnaryNegative, UnaryInverse, CastFelt, CastFelt, Select, Constant, TargetAt,
        GetUserId, GetContractId, GetCallerContractId, GetCheckpointId, GetNonce,
        SumBits,
    ]);
    // Operands are generated first (lower pool indices), then the result def
    // takes the next index — matching `injest_sfr`'s children-before-parent
    // emission so pool position always equals def index.
    match op {
        Constant => {
            push_target_const(rng, defs, pools);
        }
        Add | Sub | Mul | Div | Mod | Exp => {
            // Mirror the producer's routing for Mod/Exp: a compile-time
            // constant operand is emitted through the Constant*-specialized
            // opcode (node-ref layout — both operands still travel in
            // `inputs` as resolvable defs).
            let specialize = (op == Mod || op == Exp) && rng.chance(45);
            let lhs_const = specialize && rng.chance(45);
            let lhs = if lhs_const {
                push_target_const(rng, defs, pools)
            } else {
                target_operand(rng, defs, pools)
            };
            let rhs_const = specialize && !lhs_const;
            let rhs = if rhs_const {
                // Keep the constant divisor zero-heavy like `felt_divisor`
                // so the by-zero rejection stays in scope.
                let value = *rng.pick(&FELT_DIVISORS);
                let id = target_id(pools);
                pools.targets += 1;
                push_def(defs, Constant, id_scalar_index(id), vec![value]);
                id
            } else if op == Div || op == Mod {
                felt_divisor(rng, defs, pools)
            } else {
                target_operand(rng, defs, pools)
            };
            let op = match (op, lhs_const, rhs_const) {
                (Mod, _, true) => ModConstantDivisor,
                (Mod, true, _) => ModConstantDividend,
                (Exp, true, _) => ExpConstantBase,
                (Exp, _, true) => ExpConstantPower,
                (op, _, _) => op,
            };
            let index = pools.targets;
            pools.targets += 1;
            push_def(defs, op, index, vec![lhs, rhs]);
        }
        UnaryInverse => {
            // Zero-heavy operands exercise the invert-zero rejection.
            let operand = if rng.chance(50) {
                let id = target_id(pools);
                pools.targets += 1;
                push_def(defs, Constant, id_scalar_index(id), vec![*rng.pick(&[0u64, 0, 1, 2])]);
                id
            } else {
                target_operand(rng, defs, pools)
            };
            let index = pools.targets;
            pools.targets += 1;
            push_def(defs, op, index, vec![operand]);
        }
        // Context getters: the fuzzer's executor runs an all-zero context,
        // so the mirror resolves them to 0 too.
        GetUserId | GetContractId | GetCallerContractId | GetCheckpointId | GetNonce => {
            let index = pools.targets;
            pools.targets += 1;
            push_def(defs, op, index, vec![0]);
        }
        UnaryNegative => {
            let operand = target_operand(rng, defs, pools);
            let index = pools.targets;
            pools.targets += 1;
            push_def(defs, op, index, vec![operand]);
        }
        CastFelt => {
            // Source: u32 or bool pool.
            let src = if pools.u32s > 0 && (pools.bools == 0 || rng.chance(60)) {
                u32_operand(rng, defs, pools)
            } else {
                bool_operand(rng, defs, pools)
            };
            let index = pools.targets;
            pools.targets += 1;
            push_def(defs, op, index, vec![src]);
        }
        Select => {
            let cond = bool_operand(rng, defs, pools);
            let then = target_operand(rng, defs, pools);
            let els = target_operand(rng, defs, pools);
            let index = pools.targets;
            pools.targets += 1;
            push_def(defs, op, index, vec![cond, then, els]);
        }
        TargetAt => {
            // Only when an array/hash lane exists; index is a fresh
            // constant inside the lane's bounds (the witness bounds-asserts
            // hash indexes and panics on out-of-range array indexes).
            if let Some(array) = existing_array(rng, pools) {
                let (base, len) = match array {
                    ArrayRef::BoolArray(id, len) | ArrayRef::U32Array(id, len) | ArrayRef::Hash(id, len) | ArrayRef::TargetArray(id, len) => (id, len),
                };
                let index_value = rng.below(len as u64);
                let index_id = target_id(pools);
                pools.targets += 1;
                push_def(defs, Constant, id_scalar_index(index_id), vec![index_value]);
                let index = pools.targets;
                pools.targets += 1;
                push_def(defs, TargetAt, index, vec![base, index_id]);
            } else {
                push_target_const(rng, defs, pools);
            }
        }
        SumBits => {
            if pools.bools == 0 {
                push_target_const(rng, defs, pools);
            } else {
                // Occasionally hit the 64-input ceiling boundary.
                let n = if rng.chance(15) { 64 } else { 1 + rng.below(16) as usize };
                let bits: Vec<u64> = (0..n).map(|_| bool_operand(rng, defs, pools)).collect();
                let index = pools.targets;
                pools.targets += 1;
                push_def(defs, SumBits, index, bits);
            }
        }
        _ => unreachable!(),
    }
}

fn gen_u32_def(rng: &mut Rng, defs: &mut Vec<DPNIndexedVarDef>, pools: &mut GenPools) {
    use DPNOpType::*;
    let op = *rng.pick(&[
        U32Add,
        U32Add,
        U32Sub,
        U32Sub,
        U32Mul,
        U32Mul,
        U32Div,
        U32Mod,
        U32Exp,
        U32And,
        U32Or,
        U32Xor,
        U32ShiftLeft,
        U32ShiftRight,
        U32ShiftLeftConstantBitDistance,
        U32ShiftRightConstantBitDistance,
        U32ShiftLeftConstantValue,
        U32ShiftRightConstantValue,
        CastU32,
        ConstantU32,
    ]);
    match op {
        ConstantU32 => {
            push_u32_const(rng, defs, pools);
        }
        U32Add | U32Sub | U32Mul => {
            let lhs = u32_edge_operand(rng, defs, pools);
            // Same-def operands pin the subtraction-equality boundary
            // (x - x = 0 must be accepted, only a borrow rejects).
            let rhs = if op == U32Sub && pools.u32s > 0 && rng.chance(25) {
                lhs
            } else {
                u32_operand(rng, defs, pools)
            };
            let index = pools.u32s;
            pools.u32s += 1;
            push_def(defs, op, index, vec![lhs, rhs]);
        }
        U32Div | U32Mod => {
            let lhs = u32_operand(rng, defs, pools);
            let rhs = u32_divisor(rng, defs, pools);
            let index = pools.u32s;
            pools.u32s += 1;
            push_def(defs, op, index, vec![lhs, rhs]);
        }
        U32Exp => {
            let lhs = u32_edge_operand(rng, defs, pools);
            let rhs = u32_pow_exponent(rng, defs, pools);
            let index = pools.u32s;
            pools.u32s += 1;
            push_def(defs, op, index, vec![lhs, rhs]);
        }
        U32And
        | U32Or
        | U32Xor
        | U32ShiftLeft
        | U32ShiftRight
        | U32ShiftLeftConstantBitDistance
        | U32ShiftRightConstantBitDistance
        | U32ShiftLeftConstantValue
        | U32ShiftRightConstantValue => {
            // Constant* variants carry producer invariants: ConstantValue's
            // LEFT operand must be a ConstantU32 def (the circuit asserts
            // that side with target_as_constant). The generator therefore
            // mirrors the producer routing instead of emitting the variant
            // with an arbitrary operand. Bitwise/shift left operands stay
            // edge-biased so 0xffffffff << 31 truncation and the AND/OR
            // mask boundaries are systematic.
            let lhs = if matches!(op, U32ShiftLeftConstantValue | U32ShiftRightConstantValue) {
                push_u32_const(rng, defs, pools)
            } else {
                u32_edge_operand(rng, defs, pools)
            };
            let (rhs, op) = if matches!(op, U32And | U32Or | U32Xor) {
                // Producer routing: a ConstantU32 right operand selects the
                // U32And/Or/XorConstant variant (node-ref layout).
                if pools.u32s == 0 || rng.chance(40) {
                    let rhs = push_u32_const(rng, defs, pools);
                    let op = match op {
                        U32And => U32AndConstant,
                        U32Or => U32OrConstant,
                        _ => U32XorConstant,
                    };
                    (rhs, op)
                } else {
                    (existing_u32(rng, pools), op)
                }
            } else {
                (u32_shift_distance(rng, defs, pools), op)
            };
            let index = pools.u32s;
            pools.u32s += 1;
            push_def(defs, op, index, vec![lhs, rhs]);
        }
        CastU32 => {
            // Source: target or bool pool.
            let src = if pools.bools == 0 || rng.chance(75) {
                target_operand(rng, defs, pools)
            } else {
                bool_operand(rng, defs, pools)
            };
            let index = pools.u32s;
            pools.u32s += 1;
            push_def(defs, op, index, vec![src]);
        }
        _ => unreachable!(),
    }
}

fn gen_bool_def(rng: &mut Rng, defs: &mut Vec<DPNIndexedVarDef>, pools: &mut GenPools) {
    use DPNOpType::*;
    let op = *rng.pick(&[
        Eq,
        Eq,
        Lt,
        Lte,
        Gt,
        Gte,
        BoolAnd,
        BoolOr,
        Xor,
        Nor,
        BoolNot,
        CastBool,
        ConstantTrue,
        ConstantFalse,
        Secp256k1Verify,
    ]);
    match op {
        ConstantTrue | ConstantFalse => {
            push_bool_const(rng, defs, pools);
        }
        Eq | Lt | Lte | Gt | Gte => {
            // Comparisons over the target pool or (zero-extended) u32 pool —
            // both are compiled shapes for felt/u32 comparisons.
            let use_u32 = pools.u32s > 0 && (pools.targets == 0 || rng.chance(40));
            let (lhs, rhs) = if use_u32 {
                (u32_operand(rng, defs, pools), u32_operand(rng, defs, pools))
            } else {
                (target_operand(rng, defs, pools), target_operand(rng, defs, pools))
            };
            let index = pools.bools;
            pools.bools += 1;
            push_def(defs, op, index, vec![lhs, rhs]);
        }
        BoolAnd | BoolOr | Xor | Nor => {
            let lhs = boolish_operand(rng, defs, pools);
            let rhs = boolish_operand(rng, defs, pools);
            let index = pools.bools;
            pools.bools += 1;
            push_def(defs, op, index, vec![lhs, rhs]);
        }
        BoolNot => {
            let operand = boolish_operand(rng, defs, pools);
            let index = pools.bools;
            pools.bools += 1;
            push_def(defs, op, index, vec![operand]);
        }
        CastBool => {
            // Source: u32 or target pool (range-checked to 0/1).
            let src = if pools.targets > 0 && (pools.u32s == 0 || rng.chance(50)) {
                target_operand(rng, defs, pools)
            } else {
                u32_operand(rng, defs, pools)
            };
            let index = pools.bools;
            pools.bools += 1;
            push_def(defs, op, index, vec![src]);
        }
        Secp256k1Verify => {
            // Random words: pk/sig words stay inside the u32 lane (the
            // witness asserts the word range); msg words are full felts.
            // Verification almost surely fails — the crafted-signature
            // generator covers the verify-to-true path.
            let mut inputs = Vec::with_capacity(36);
            for _ in 0..32 {
                inputs.push(u32_operand(rng, defs, pools));
            }
            for _ in 0..4 {
                inputs.push(target_operand(rng, defs, pools));
            }
            let index = pools.bools;
            pools.bools += 1;
            push_def(defs, Secp256k1Verify, index, inputs);
        }
        _ => unreachable!(),
    }
}

pub fn gen_program(rng: &mut Rng) -> Program {
    let mut defs: Vec<DPNIndexedVarDef> = Vec::new();
    let mut pools = GenPools::default();

    // Positional inputs first (their defs populate the pools).
    let n_inputs = 2 + rng.below(3) as usize;
    let mut input_values = Vec::with_capacity(n_inputs);
    let mut input_kinds = Vec::with_capacity(n_inputs);
    for i in 0..n_inputs {
        let roll = rng.below(100);
        if roll < 50 {
            // Felt input.
            let value = felt_literal(rng);
            let id = target_id(&pools);
            pools.targets += 1;
            push_def(&mut defs, DPNOpType::InputTarget, id_scalar_index(id), vec![i as u64]);
            input_values.push(value);
            input_kinds.push(DPNBuiltInDataType::Target);
        } else if roll < 85 {
            // u32 input.
            let value = u32_literal(rng);
            let id = u32_id(&pools);
            pools.u32s += 1;
            push_def(&mut defs, DPNOpType::U32InputTarget, id_scalar_index(id), vec![i as u64]);
            input_values.push(value as u64);
            input_kinds.push(DPNBuiltInDataType::U32Target);
        } else {
            // Bool input.
            let value = rng.boolean() as u64;
            let id = bool_id(&pools);
            pools.bools += 1;
            push_def(&mut defs, DPNOpType::BoolInputTarget, id_scalar_index(id), vec![i as u64]);
            input_values.push(value);
            input_kinds.push(DPNBuiltInDataType::Bool);
        }
    }

    let n_defs = 10 + rng.below(16) as usize;
    let mut crafted_secp_index = None;
    for _ in 0..n_defs {
        let roll = rng.below(100);
        if roll < 35 {
            gen_u32_def(rng, &mut defs, &mut pools);
        } else if roll < 60 {
            gen_target_def(rng, &mut defs, &mut pools);
        } else if roll < 80 {
            gen_bool_def(rng, &mut defs, &mut pools);
        } else if roll < 92 {
            gen_array_def(rng, &mut defs, &mut pools);
        } else if rng.chance(50) {
            // Occasional k256-crafted signature that must verify to true.
            crafted_secp_index = Some(gen_crafted_secp(rng, &mut defs, &mut pools));
        } else {
            gen_bool_def(rng, &mut defs, &mut pools);
        }
    }

    Program {
        input_values,
        input_kinds,
        defs,
        crafted_secp_index,
    }
}

const SPLIT_WIDTHS: [u64; 7] = [1, 4, 8, 12, 16, 32, 64];

/// Array- and hash-lane producers: SplitBits -> bool arrays (compiled
/// 3-input layout), Keccak256 -> u32 arrays, HashNoPad/HashTwoToOne ->
/// Poseidon hashes.
fn gen_array_def(rng: &mut Rng, defs: &mut Vec<DPNIndexedVarDef>, pools: &mut GenPools) {
    use DPNOpType::*;
    let op = *rng.pick(&[
        SplitBits,
        SplitBits,
        Keccak256,
        Keccak256,
        HashNoPad,
        HashNoPad,
        HashTwoToOne,
        DivRem4,
        GetUserPublicKeyHash,
        GetSessionProofTreeRoot,
    ]);
    match op {
        SplitBits => {
            let num_bits = *rng.pick(&SPLIT_WIDTHS);
            // 70%: a fresh constant guaranteed to fit; otherwise any felt
            // operand, which may exceed num_bits and take the rejection.
            let value_id = if rng.chance(70) {
                let value = if num_bits >= 64 {
                    rng.next_u64()
                } else {
                    rng.next_u64() & ((1u64 << num_bits) - 1)
                };
                let id = target_id(pools);
                pools.targets += 1;
                push_def(defs, Constant, id_scalar_index(id), vec![value]);
                id
            } else {
                target_operand(rng, defs, pools)
            };
            // The redundant num_bits constant child compile keeps alive.
            let nb_const = target_id(pools);
            pools.targets += 1;
            push_def(defs, Constant, id_scalar_index(nb_const), vec![num_bits]);
            let id = bool_array_id(pools);
            pools.bool_array_lens.insert(id, num_bits as usize);
            pools.bool_arrays += 1;
            push_def(defs, SplitBits, id_scalar_index(id), vec![num_bits, value_id, nb_const]);
        }
        Keccak256 => {
            let n_words = 1 + rng.below(8) as usize;
            let mut words = Vec::with_capacity(n_words);
            for _ in 0..n_words {
                // u32-lane operands always fit; felt operands may exceed the
                // u32 lane and take the range-check rejection.
                words.push(if rng.chance(70) {
                    u32_operand(rng, defs, pools)
                } else {
                    target_operand(rng, defs, pools)
                });
            }
            let id = u32_array_id(pools);
            pools.u32_arrays += 1;
            push_def(defs, Keccak256, id_scalar_index(id), words);
        }
        HashNoPad => {
            let n_words = 1 + rng.below(8) as usize;
            let words: Vec<u64> = (0..n_words).map(|_| target_operand(rng, defs, pools)).collect();
            let id = hash_id(pools);
            pools.hashes += 1;
            push_def(defs, HashNoPad, id_scalar_index(id), words);
        }
        HashTwoToOne => {
            let words: Vec<u64> = (0..8).map(|_| target_operand(rng, defs, pools)).collect();
            let id = hash_id(pools);
            pools.hashes += 1;
            push_def(defs, HashTwoToOne, id_scalar_index(id), words);
        }
        DivRem4 => {
            let value = target_operand(rng, defs, pools);
            let id = target_array_id(pools);
            pools.target_arrays += 1;
            push_def(defs, DivRem4, id_scalar_index(id), vec![value]);
        }
        // Context hash getters: all-zero context in the fuzzer's executor.
        GetUserPublicKeyHash | GetSessionProofTreeRoot => {
            let id = hash_id(pools);
            pools.hashes += 1;
            push_def(defs, op, id_scalar_index(id), vec![0]);
        }
        _ => unreachable!(),
    }
}

/// k256-crafted Secp256k1Verify whose words are packed exactly the way the
/// executor arm unpacks them (LE limb bytes, whole sequence reversed), so
/// verification must succeed. Returns the def's bool-pool index.
fn gen_crafted_secp(rng: &mut Rng, defs: &mut Vec<DPNIndexedVarDef>, pools: &mut GenPools) -> usize {
    use k256::ecdsa::{
        signature::hazmat::PrehashSigner,
        Signature, SigningKey, VerifyingKey,
    };

    let mut seed = [0u8; 32];
    for b in seed.iter_mut() {
        *b = rng.next_u64() as u8;
    }
    let mut msg = [0u8; 32];
    for b in msg.iter_mut() {
        *b = rng.next_u64() as u8;
    }
    let sk = SigningKey::from_slice(&seed).expect("valid signing seed");
    let vk = VerifyingKey::from(&sk);
    let point = vk.to_encoded_point(false);
    let x = point.x().unwrap();
    let y = point.y().unwrap();
    let sig: Signature = sk.sign_prehash(&msg).expect("k256 sign");
    let sig_bytes = sig.to_bytes();

    // words_of packs 32 big-endian bytes into 8 u32 words such that the
    // executor's `flat_map(to_le_bytes).rev()` unpacking reproduces the
    // original bytes: word i holds bytes [(7-i)*4, (7-i)*4+4).
    let words_of = |b: &[u8]| -> Vec<u64> {
        (0..8)
            .map(|i| u32::from_be_bytes(b[(7 - i) * 4..(7 - i) * 4 + 4].try_into().unwrap()) as u64)
            .collect()
    };
    // msg words are full felts: 32 BE bytes -> 4 u64 words, word j holds
    // bytes [(3-j)*8, (3-j)*8+8).
    let msg_words: Vec<u64> = (0..4)
        .map(|j| u64::from_be_bytes(msg[(3 - j) * 8..(3 - j) * 8 + 8].try_into().unwrap()))
        .collect();

    let mut inputs = Vec::with_capacity(36);
    let word_groups = [
        words_of(x.as_slice()),
        words_of(y.as_slice()),
        words_of(&sig_bytes[0..32]),
        words_of(&sig_bytes[32..64]),
    ];
    for group in word_groups {
        for w in group {
            let id = target_id(pools);
            pools.targets += 1;
            push_def(defs, DPNOpType::Constant, id_scalar_index(id), vec![w]);
            inputs.push(id);
        }
    }
    for w in msg_words {
        let id = target_id(pools);
        pools.targets += 1;
        push_def(defs, DPNOpType::Constant, id_scalar_index(id), vec![w]);
        inputs.push(id);
    }
    let index = pools.bools;
    pools.bools += 1;
    push_def(defs, DPNOpType::Secp256k1Verify, index, inputs);
    index
}

// ---------- native mirror ----------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MirrorErr {
    Overflow,
    DivZero,
    InvalidCast,
    InvalidSplitBits,
}

#[derive(Default)]
pub struct MirrorPools {
    pub targets: Vec<u64>,
    pub u32s: Vec<u32>,
    pub bools: Vec<bool>,
    pub target_arrays: Vec<Vec<u64>>,
    pub bool_arrays: Vec<Vec<bool>>,
    pub u32_arrays: Vec<Vec<u32>>,
    pub hashes: Vec<[u64; 4]>,
}

fn f_add(a: u64, b: u64) -> u64 {
    ((a as u128 + b as u128) % GOLDILOCKS_P) as u64
}
fn f_sub(a: u64, b: u64) -> u64 {
    ((GOLDILOCKS_P + a as u128 - b as u128) % GOLDILOCKS_P) as u64
}
fn f_mul(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % GOLDILOCKS_P) as u64
}
fn f_pow(a: u64, e: u64) -> u64 {
    let mut result: u128 = 1;
    let mut base = a as u128 % GOLDILOCKS_P;
    let mut exp = e as u128;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * base % GOLDILOCKS_P;
        }
        base = base * base % GOLDILOCKS_P;
        exp >>= 1;
    }
    result as u64
}
fn f_div(a: u64, b: u64) -> Result<u64, MirrorErr> {
    if b == 0 {
        Err(MirrorErr::DivZero)
    } else {
        Ok(f_mul(a, f_pow(b, (GOLDILOCKS_P - 2) as u64)))
    }
}

/// `base^exp mod p` reduced in exact u128 arithmetic, matching the
/// executor's `Field::exp_u64`.
fn u32_pow_field(base: u32, exp: u32) -> u64 {
    f_pow(base as u64, exp as u64)
}

impl MirrorPools {
    /// resolve_target: bools become 0/1, u32s zero-extend.
    fn as_target(&self, id: u64) -> u64 {
        match decode_indexed_op_id(id) {
            (DPNBuiltInDataType::Bool, i) => self.bools[i] as u64,
            (DPNBuiltInDataType::Target, i) => self.targets[i],
            (DPNBuiltInDataType::U32Target, i) => self.u32s[i] as u64,
            _ => panic!("mirror: non-scalar target ref"),
        }
    }

    fn as_u32(&self, id: u64) -> u32 {
        match decode_indexed_op_id(id) {
            (DPNBuiltInDataType::U32Target, i) => self.u32s[i],
            (DPNBuiltInDataType::Bool, i) => self.bools[i] as u32,
            (DPNBuiltInDataType::Target, i) => self.targets[i] as u32,
            _ => panic!("mirror: non-scalar u32 ref"),
        }
    }

    fn as_bool(&self, id: u64) -> bool {
        match decode_indexed_op_id(id) {
            (DPNBuiltInDataType::Bool, i) => self.bools[i],
            _ => panic!("mirror: bool ref must point at the bool pool"),
        }
    }

    /// Boolean-algebra operand over any scalar lane: resolve_bool reads the
    /// bool lane directly and enforces 0/1 on Target/U32 refs.
    fn as_bool_checked(&self, id: u64) -> Result<bool, MirrorErr> {
        match decode_indexed_op_id(id) {
            (DPNBuiltInDataType::Bool, i) => Ok(self.bools[i]),
            (DPNBuiltInDataType::Target, i) => match self.targets[i] {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(MirrorErr::InvalidCast),
            },
            (DPNBuiltInDataType::U32Target, i) => match self.u32s[i] as u64 {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(MirrorErr::InvalidCast),
            },
            _ => panic!("mirror: non-scalar bool ref"),
        }
    }
}

fn apply_cmp(op: DPNOpType, l: u64, r: u64) -> bool {
    match op {
        DPNOpType::Eq => l == r,
        DPNOpType::Lt => l < r,
        DPNOpType::Lte => l <= r,
        DPNOpType::Gt => l > r,
        DPNOpType::Gte => l >= r,
        _ => unreachable!(),
    }
}

/// Evaluate defs sequentially; on error, report the def index and class.
pub fn mirror_eval(program: &Program) -> Result<MirrorPools, (usize, MirrorErr)> {
    let mut p = MirrorPools::default();
    for (def_index, def) in program.defs.iter().enumerate() {
        use DPNOpType::*;
        let err = |e: MirrorErr| (def_index, e);
        match def.op_type {
            InputTarget => {
                let v = program.input_values[def.inputs[0] as usize];
                p.targets.push(v);
            }
            U32InputTarget => {
                let v = program.input_values[def.inputs[0] as usize] as u32;
                p.u32s.push(v);
            }
            BoolInputTarget => {
                let v = program.input_values[def.inputs[0] as usize] != 0;
                p.bools.push(v);
            }
            Constant => p.targets.push(def.inputs[0]),
            ConstantU32 => p.u32s.push(def.inputs[0] as u32),
            ConstantTrue => p.bools.push(true),
            ConstantFalse => p.bools.push(false),

            Add => p.targets.push(f_add(p.as_target(def.inputs[0]), p.as_target(def.inputs[1]))),
            Sub => p.targets.push(f_sub(p.as_target(def.inputs[0]), p.as_target(def.inputs[1]))),
            Mul => p.targets.push(f_mul(p.as_target(def.inputs[0]), p.as_target(def.inputs[1]))),
            Div => {
                let r = p.as_target(def.inputs[1]);
                let v = f_div(p.as_target(def.inputs[0]), r).map_err(err)?;
                p.targets.push(v);
            }
            Mod | ModConstantDividend | ModConstantDivisor => {
                let (l, r) = (p.as_target(def.inputs[0]), p.as_target(def.inputs[1]));
                if r == 0 {
                    return Err(err(MirrorErr::DivZero));
                }
                p.targets.push(l % r);
            }
            Exp | ExpConstantPower | ExpConstantBase => {
                p.targets.push(f_pow(p.as_target(def.inputs[0]), p.as_target(def.inputs[1])))
            }
            UnaryInverse => {
                let v = p.as_target(def.inputs[0]);
                let inv = f_div(1, v).map_err(err)?; // zero maps to DivZero ("invert zero")
                p.targets.push(inv);
            }
            UnaryNegative => {
                let v = p.as_target(def.inputs[0]);
                p.targets.push(((GOLDILOCKS_P - v as u128 % GOLDILOCKS_P) % GOLDILOCKS_P) as u64);
            }
            Select => {
                let cond = p.as_target(def.inputs[0]);
                let v = if cond != 0 {
                    p.as_target(def.inputs[1])
                } else {
                    p.as_target(def.inputs[2])
                };
                p.targets.push(v);
            }

            Eq | Lt | Lte | Gt | Gte => {
                let v = apply_cmp(def.op_type, p.as_target(def.inputs[0]), p.as_target(def.inputs[1]));
                p.bools.push(v);
            }
            BoolAnd => {
                let (a, b) = (p.as_bool_checked(def.inputs[0]).map_err(err)?, p.as_bool_checked(def.inputs[1]).map_err(err)?);
                p.bools.push(a && b);
            }
            BoolOr => {
                let (a, b) = (p.as_bool_checked(def.inputs[0]).map_err(err)?, p.as_bool_checked(def.inputs[1]).map_err(err)?);
                p.bools.push(a || b);
            }
            Xor => {
                let (a, b) = (p.as_bool_checked(def.inputs[0]).map_err(err)?, p.as_bool_checked(def.inputs[1]).map_err(err)?);
                p.bools.push(a ^ b);
            }
            Nor => {
                let (a, b) = (p.as_bool_checked(def.inputs[0]).map_err(err)?, p.as_bool_checked(def.inputs[1]).map_err(err)?);
                p.bools.push(!(a || b));
            }
            BoolNot => {
                let v = p.as_bool_checked(def.inputs[0]).map_err(err)?;
                p.bools.push(!v);
            }

            CastFelt => {
                let v = match decode_indexed_op_id(def.inputs[0]) {
                    (DPNBuiltInDataType::U32Target, i) => p.u32s[i] as u64,
                    (DPNBuiltInDataType::Bool, i) => p.bools[i] as u64,
                    (DPNBuiltInDataType::Target, i) => p.targets[i],
                    _ => panic!("mirror: bad CastFelt source"),
                };
                p.targets.push(v);
            }
            CastU32 => {
                let v = match decode_indexed_op_id(def.inputs[0]) {
                    (DPNBuiltInDataType::Target, i) => {
                        if p.targets[i] > 0xffff_ffff {
                            return Err(err(MirrorErr::InvalidCast));
                        }
                        p.targets[i] as u32
                    }
                    (DPNBuiltInDataType::U32Target, i) => p.u32s[i],
                    (DPNBuiltInDataType::Bool, i) => p.bools[i] as u32,
                    _ => panic!("mirror: bad CastU32 source"),
                };
                p.u32s.push(v);
            }
            CastBool => {
                let v = match decode_indexed_op_id(def.inputs[0]) {
                    (DPNBuiltInDataType::U32Target, i) => {
                        if p.u32s[i] > 1 {
                            return Err(err(MirrorErr::InvalidCast));
                        }
                        p.u32s[i] != 0
                    }
                    (DPNBuiltInDataType::Target, i) => {
                        if p.targets[i] > 1 {
                            return Err(err(MirrorErr::InvalidCast));
                        }
                        p.targets[i] != 0
                    }
                    (DPNBuiltInDataType::Bool, i) => p.bools[i],
                    _ => panic!("mirror: bad CastBool source"),
                };
                p.bools.push(v);
            }

            U32Add => {
                let (l, r) = (p.as_u32(def.inputs[0]), p.as_u32(def.inputs[1]));
                if l as u64 + r as u64 > 0xffff_ffff {
                    return Err(err(MirrorErr::Overflow));
                }
                p.u32s.push(l + r);
            }
            U32Sub => {
                let (l, r) = (p.as_u32(def.inputs[0]), p.as_u32(def.inputs[1]));
                // Checked subtraction: equality is allowed (x - x = 0), only
                // a borrow rejects.
                if l < r {
                    return Err(err(MirrorErr::Overflow));
                }
                p.u32s.push(l - r);
            }
            U32Mul => {
                let (l, r) = (p.as_u32(def.inputs[0]), p.as_u32(def.inputs[1]));
                if l as u64 * r as u64 > 0xffff_ffff {
                    return Err(err(MirrorErr::Overflow));
                }
                p.u32s.push(l * r);
            }
            U32Div => {
                let (l, r) = (p.as_u32(def.inputs[0]), p.as_u32(def.inputs[1]));
                if r == 0 {
                    return Err(err(MirrorErr::DivZero));
                }
                p.u32s.push(l / r);
            }
            U32Mod => {
                let (l, r) = (p.as_u32(def.inputs[0]), p.as_u32(def.inputs[1]));
                if r == 0 {
                    return Err(err(MirrorErr::DivZero));
                }
                p.u32s.push(l % r);
            }
            U32Exp => {
                let (l, r) = (p.as_u32(def.inputs[0]), p.as_u32(def.inputs[1]));
                let v = u32_pow_field(l, r);
                if v > 0xffff_ffff {
                    return Err(err(MirrorErr::Overflow));
                }
                p.u32s.push(v as u32);
            }
            U32And | U32AndConstant => p.u32s.push(p.as_u32(def.inputs[0]) & p.as_u32(def.inputs[1])),
            U32Or | U32OrConstant => p.u32s.push(p.as_u32(def.inputs[0]) | p.as_u32(def.inputs[1])),
            U32Xor | U32XorConstant => p.u32s.push(p.as_u32(def.inputs[0]) ^ p.as_u32(def.inputs[1])),
            U32ShiftLeft | U32ShiftLeftConstantBitDistance | U32ShiftLeftConstantValue => {
                let (l, r) = (p.as_u32(def.inputs[0]), p.as_u32(def.inputs[1]));
                p.u32s.push(if r >= 32 { 0 } else { l << r });
            }
            U32ShiftRight | U32ShiftRightConstantBitDistance | U32ShiftRightConstantValue => {
                let (l, r) = (p.as_u32(def.inputs[0]), p.as_u32(def.inputs[1]));
                p.u32s.push(if r >= 32 { 0 } else { l >> r });
            }

            // Array- and hash-lane ops.
            SplitBits => {
                let num_bits = def.inputs[0];
                let value = p.as_target(def.inputs[1]);
                if num_bits < 64 && value >= 1u64 << num_bits {
                    return Err(err(MirrorErr::InvalidSplitBits));
                }
                p.bool_arrays.push((0..num_bits).map(|i| (value >> i) & 1 == 1).collect());
            }
            Keccak256 => {
                let words: Vec<u64> = def.inputs.iter().map(|&id| p.as_target(id)).collect();
                if words.iter().any(|&w| w > 0xffff_ffff) {
                    return Err(err(MirrorErr::InvalidCast));
                }
                let mut bytes = Vec::with_capacity(words.len() * 4);
                for w in &words {
                    bytes.extend_from_slice(&(*w as u32).to_be_bytes());
                }
                let mut digest = [0u8; 32];
                let mut k = Keccak::v256();
                k.update(&bytes);
                k.finalize(&mut digest);
                p.u32_arrays.push(
                    digest
                        .chunks_exact(4)
                        .take(8)
                        .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
                        .collect(),
                );
            }
            HashNoPad => {
                let args: Vec<GoldilocksField> = def
                    .inputs
                    .iter()
                    .map(|&id| GoldilocksField::from_noncanonical_u64(p.as_target(id)))
                    .collect();
                let h = PoseidonHash::hash_no_pad(&args);
                p.hashes.push(h.elements.map(|e| e.to_canonical_u64()));
            }
            HashTwoToOne => {
                let vals: Vec<u64> = def.inputs.iter().map(|&id| p.as_target(id)).collect();
                let gl: Vec<GoldilocksField> =
                    vals.iter().map(|&v| GoldilocksField::from_noncanonical_u64(v)).collect();
                let left = plonky2::hash::hash_types::HashOut {
                    elements: [gl[0], gl[1], gl[2], gl[3]],
                };
                let right = plonky2::hash::hash_types::HashOut {
                    elements: [gl[4], gl[5], gl[6], gl[7]],
                };
                let h = PoseidonHash::two_to_one(left, right);
                p.hashes.push(h.elements.map(|e| e.to_canonical_u64()));
            }
            TargetAt => {
                let (lane, i) = decode_indexed_op_id(def.inputs[0]);
                let idx = p.as_target(def.inputs[1]) as usize;
                let v = match lane {
                    DPNBuiltInDataType::HashOut => {
                        assert!(idx < 4, "Invalid index in hash");
                        p.hashes[i][idx]
                    }
                    DPNBuiltInDataType::BoolArray => p.bool_arrays[i][idx] as u64,
                    DPNBuiltInDataType::TargetArray => p.target_arrays[i][idx],
                    DPNBuiltInDataType::U32TargetArray => p.u32_arrays[i][idx] as u64,
                    other => panic!("mirror: unexpected TargetAt base lane {other:?}"),
                };
                p.targets.push(v);
            }
            SumBits => {
                // Weighted binary reconstruction reduced mod p.
                let mut sum: u64 = 0;
                for (i, &id) in def.inputs.iter().enumerate() {
                    if p.as_bool(id) {
                        sum += 1 << i;
                    }
                }
                p.targets.push(GoldilocksField::from_noncanonical_u64(sum).to_canonical_u64());
            }
            DivRem4 => {
                let value = p.as_target(def.inputs[0]);
                p.target_arrays.push(vec![value >> 2, value & 3]);
            }
            GetUserId | GetContractId | GetCallerContractId | GetCheckpointId | GetNonce => p.targets.push(0),
            GetUserPublicKeyHash | GetSessionProofTreeRoot => p.hashes.push([0; 4]),
            Secp256k1Verify => {
                let inputs: Vec<u64> = def.inputs.iter().map(|&id| p.as_target(id)).collect();
                p.bools.push(secp_verify_mirror(&inputs));
            }
            other => panic!("mirror: unexpected op {other:?}"),
        }
    }
    Ok(p)
}

// ---------- executor harness ----------

/// Transcription of the witness Secp256k1Verify arm (k256): 36 words =
/// pk.x[8] ++ pk.y[8] ++ r[8] ++ s[8] as u32 limbs, then msg[4] as felt
/// limbs. Limbs serialize as LE bytes with each group's whole byte sequence
/// reversed (== big-endian). Malformed keys/signatures fail verification
/// (false), never abort.
fn secp_verify_mirror(inputs: &[u64]) -> bool {
    use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};

    assert_eq!(inputs.len(), 36, "Secp256k1Verify input length must be 36");
    let words_be = |ws: &[u64]| -> Vec<u8> {
        ws.iter().flat_map(|&w| (w as u32).to_le_bytes()).rev().collect()
    };

    let mut pk_sec1_bytes = vec![0x04];
    pk_sec1_bytes.extend(words_be(&inputs[0..8]));
    pk_sec1_bytes.extend(words_be(&inputs[8..16]));

    let mut signature_bytes = words_be(&inputs[16..24]);
    signature_bytes.extend(words_be(&inputs[24..32]));

    let msg_bytes: Vec<u8> = inputs[32..36].iter().flat_map(|&w| w.to_le_bytes()).rev().collect();

    let Ok(vk) = VerifyingKey::from_sec1_bytes(&pk_sec1_bytes) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&signature_bytes) else {
        return false;
    };
    vk.verify_prehash(&msg_bytes, &signature).is_ok()
}


pub fn classify_rejection(msg: &str) -> Option<MirrorErr> {
    let lower = msg.to_lowercase();
    if lower.contains("value too large") || lower.contains("value too low") {
        Some(MirrorErr::Overflow)
    } else if lower.contains("by zero") || lower.contains("invert zero") {
        Some(MirrorErr::DivZero)
    } else if lower.contains("invalid bool value") || lower.contains("invalid u32 value") {
        Some(MirrorErr::InvalidCast)
    } else if lower.contains("does not fit in") {
        Some(MirrorErr::InvalidSplitBits)
    } else {
        None
    }
}

// ---------- differential loop ----------


pub fn dump_program(program: &Program) -> String {
    let mut out = String::from("inputs: ");
    for (i, (kind, value)) in program.input_kinds.iter().zip(&program.input_values).enumerate() {
        out.push_str(&format!("{kind:?}[{i}]={value} "));
    }
    out.push('\n');
    for (i, def) in program.defs.iter().enumerate() {
        let inputs = def
            .inputs
            .iter()
            .map(|x| {
                let (t, idx) = decode_indexed_op_id(*x);
                format!("{t:?}:{idx}")
            })
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("  #{i:3} {:?} index={} inputs=[{}]\n", def.op_type, def.index, inputs));
    }
    out
}

pub fn pools_diff(mirror: &MirrorPools, executor: &SimpleDPNExecutor<GoldilocksField>) -> String {
    let targets = mirror
        .targets
        .iter()
        .zip(executor.targets.iter())
        .enumerate()
        .filter_map(|(i, (m, e))| (*m != e.to_canonical_u64()).then(|| format!("target[{i}]: mirror={m} exec={}", e.to_canonical_u64())))
        .collect::<Vec<_>>();
    let u32s = mirror
        .u32s
        .iter()
        .zip(executor.u32s.iter())
        .enumerate()
        .filter_map(|(i, (m, e))| (m != e).then(|| format!("u32[{i}]: mirror={m} exec={e}")))
        .collect::<Vec<_>>();
    let bools = mirror
        .bools
        .iter()
        .zip(executor.bools.iter())
        .enumerate()
        .filter_map(|(i, (m, e))| (m != e).then(|| format!("bool[{i}]: mirror={m} exec={e}")))
        .collect::<Vec<_>>();
    let target_arrays = mirror
        .target_arrays
        .iter()
        .zip(executor.target_arrays.iter())
        .enumerate()
        .filter_map(|(i, (m, e))| {
            let exec: Vec<u64> = e.iter().map(|f| f.to_canonical_u64()).collect();
            (*m != exec).then(|| format!("target_array[{i}]: mirror={m:?} exec={exec:?}"))
        })
        .collect::<Vec<_>>();
    let bool_arrays = mirror
        .bool_arrays
        .iter()
        .zip(executor.bool_arrays.iter())
        .enumerate()
        .filter_map(|(i, (m, e))| (m != e).then(|| format!("bool_array[{i}]: mirror={m:?} exec={e:?}")))
        .collect::<Vec<_>>();
    let u32_arrays = mirror
        .u32_arrays
        .iter()
        .zip(executor.u32_arrays.iter())
        .enumerate()
        .filter_map(|(i, (m, e))| (m != e).then(|| format!("u32_array[{i}]: mirror={m:?} exec={e:?}")))
        .collect::<Vec<_>>();
    let hashes = mirror
        .hashes
        .iter()
        .zip(executor.hashes.iter())
        .enumerate()
        .filter_map(|(i, (m, e))| {
            let exec: Vec<u64> = e.iter().map(|f| f.to_canonical_u64()).collect();
            (*m != exec[..]).then(|| format!("hash[{i}]: mirror={m:?} exec={exec:?}"))
        })
        .collect::<Vec<_>>();
    let mut out = String::new();
    if mirror.targets.len() != executor.targets.len() {
        out.push_str(&format!(
            "target pool length: mirror={} exec={}\n",
            mirror.targets.len(),
            executor.targets.len()
        ));
    }
    if mirror.u32s.len() != executor.u32s.len() {
        out.push_str(&format!("u32 pool length: mirror={} exec={}\n", mirror.u32s.len(), executor.u32s.len()));
    }
    if mirror.bools.len() != executor.bools.len() {
        out.push_str(&format!(
            "bool pool length: mirror={} exec={}\n",
            mirror.bools.len(),
            executor.bools.len()
        ));
    }
    if mirror.target_arrays.len() != executor.target_arrays.len() {
        out.push_str(&format!(
            "target_array pool length: mirror={} exec={}\n",
            mirror.target_arrays.len(),
            executor.target_arrays.len()
        ));
    }
    if mirror.bool_arrays.len() != executor.bool_arrays.len() {
        out.push_str(&format!(
            "bool_array pool length: mirror={} exec={}\n",
            mirror.bool_arrays.len(),
            executor.bool_arrays.len()
        ));
    }
    if mirror.u32_arrays.len() != executor.u32_arrays.len() {
        out.push_str(&format!(
            "u32_array pool length: mirror={} exec={}\n",
            mirror.u32_arrays.len(),
            executor.u32_arrays.len()
        ));
    }
    if mirror.hashes.len() != executor.hashes.len() {
        out.push_str(&format!(
            "hash pool length: mirror={} exec={}\n",
            mirror.hashes.len(),
            executor.hashes.len()
        ));
    }
    for line in targets
        .iter()
        .chain(u32s.iter())
        .chain(bools.iter())
        .chain(bool_arrays.iter())
        .chain(target_arrays.iter())
        .chain(u32_arrays.iter())
        .chain(hashes.iter())
    {
        out.push_str(line);
        out.push('\n');
    }
    if out.is_empty() {
        out.push_str("<pools equal>\n");
    }
    out
}


pub fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic>".to_string()
    }
}

/// Wrap a generated program in a DPNFunctionCircuitDefinition. Scalar-lane
/// defs (Target/U32/Bool) are registered as outputs so executors that only
/// expose outputs (VmExecutor) can be differentially compared; array/hash
/// contents are already read back into the target pool by generated
/// TargetAt defs.
pub fn program_definition(program: &Program) -> DPNFunctionCircuitDefinition {
    let circuit_inputs: Vec<u64> = program
        .defs
        .iter()
        .filter(|d| {
            matches!(
                d.op_type,
                DPNOpType::InputTarget | DPNOpType::U32InputTarget | DPNOpType::BoolInputTarget
            )
        })
        .map(|d| encode_indexed_op_id(d.data_type, d.index))
        .collect();
    let circuit_outputs: Vec<u64> = program
        .defs
        .iter()
        .filter(|d| {
            matches!(
                d.data_type,
                DPNBuiltInDataType::Target | DPNBuiltInDataType::U32Target | DPNBuiltInDataType::Bool
            )
        })
        .map(|d| encode_indexed_op_id(d.data_type, d.index))
        .collect();
    DPNFunctionCircuitDefinition {
        name: "fuzz".to_string(),
        method_id: 0,
        circuit_inputs,
        circuit_outputs,
        state_commands: vec![],
        state_command_resolution_indices: vec![],
        assertions: vec![],
        events: vec![],
        definitions: program.defs.clone(),
    }
}

/// Expected scalar-output sequence in definition order (Target/U32/Bool
/// only), matching `program_definition`'s circuit_outputs.
pub fn expected_scalar_outputs(mirror: &MirrorPools, program: &Program) -> Vec<u64> {
    program
        .defs
        .iter()
        .filter(|d| {
            matches!(
                d.data_type,
                DPNBuiltInDataType::Target | DPNBuiltInDataType::U32Target | DPNBuiltInDataType::Bool
            )
        })
        .map(|d| match d.data_type {
            DPNBuiltInDataType::Target => mirror.targets[d.index],
            DPNBuiltInDataType::U32Target => mirror.u32s[d.index] as u64,
            _ => mirror.bools[d.index] as u64,
        })
        .collect()
}

/// Generate the program for a seed and run the positive structural oracle:
/// the generator mirrors compile_exec's emission conventions, so every
/// generated program must also pass the definition validator.
pub fn program_for_seed(seed: u64) -> Program {
    let mut rng = Rng::new(seed);
    let program = gen_program(&mut rng);

    let defn = program_definition(&program);
    if let Err(e) = validate_function_definition(&defn) {
        panic!("generated program failed validation (seed {seed}): {e}\n{}", dump_program(&program));
    }
    program
}

// ---------- SymFeltStore reverse construction (for the core_eval harness) ----------

use crate::dpn::ops::sym_felt::{SymFeltRef, SymFeltRefValue};
use crate::dpn::ops::sym_felt_store::SymFeltStore;

/// Reverse-map a generated compiled program into the pre-compilation
/// SymFeltStore graph core_eval natively consumes: every def becomes a
/// SymFeltRefValue whose inputs are the mapped refs of the def's operand
/// ids, matching the producer's node shapes (SplitBits keeps its
/// const_param num_bits and the [value, num_bits_const] children, etc.).
pub struct SymProgram {
    pub store: SymFeltStore,
    /// Per-lane SymFeltRef for each def, indexed like the compiled pools.
    pub refs: std::collections::HashMap<(DPNBuiltInDataType, usize), SymFeltRef>,
}

pub fn build_sym_store(program: &Program) -> SymProgram {
    let mut store = SymFeltStore::new();
    let mut refs = std::collections::HashMap::new();
    let mut map = |id: u64, refs: &std::collections::HashMap<(DPNBuiltInDataType, usize), SymFeltRef>| -> SymFeltRef {
        let (lane, index) = decode_indexed_op_id(id);
        if lane == DPNBuiltInDataType::Target
            || lane == DPNBuiltInDataType::Bool
            || lane == DPNBuiltInDataType::U32Target
        {
            refs[&(lane, index)]
        } else {
            // Array/hash-lane operands (TargetAt bases): map through too.
            refs[&(lane, index)]
        }
    };
    for def in &program.defs {
        let r = match def.op_type {
            DPNOpType::InputTarget => SymFeltRef::new_input(def.inputs[0], DPNBuiltInDataType::Target),
            DPNOpType::U32InputTarget => SymFeltRef::new_input(def.inputs[0], DPNBuiltInDataType::U32Target),
            DPNOpType::BoolInputTarget => SymFeltRef::new_input(def.inputs[0], DPNBuiltInDataType::Bool),
            DPNOpType::Constant => SymFeltRef::new_constant(def.inputs[0]),
            DPNOpType::ConstantU32 => SymFeltRef::new_constant_u32(def.inputs[0] as u32),
            DPNOpType::ConstantTrue | DPNOpType::ConstantFalse
            | DPNOpType::GetUserId | DPNOpType::GetContractId | DPNOpType::GetCallerContractId
            | DPNOpType::GetCheckpointId | DPNOpType::GetNonce | DPNOpType::GetUserPublicKeyHash
            | DPNOpType::GetSessionProofTreeRoot => SymFeltRef(
                ((def.op_type as u128) << 112) | 0,
            ),
            DPNOpType::SplitBits => {
                // Producer shape: const_param = num_bits, children
                // [value, num_bits_const].
                let value = map(def.inputs[1], &refs);
                let nb_const = map(def.inputs[2], &refs);
                store.insert(SymFeltRefValue {
                    op_type: DPNOpType::SplitBits,
                    const_param: def.inputs[0],
                    inputs: vec![value, nb_const],
                })
            }
            _ => {
                let inputs = def.inputs.iter().map(|&id| map(id, &refs)).collect();
                store.insert(SymFeltRefValue {
                    op_type: def.op_type,
                    const_param: 0,
                    inputs,
                })
            }
        };
        refs.insert((def.data_type, def.index), r);
    }
    SymProgram { store, refs }
}
