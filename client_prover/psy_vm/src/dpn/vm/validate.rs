//! Structural validation of compiled DPN programs.
//!
//! A `DPNFunctionCircuitDefinition` may arrive from untrusted storage
//! (on-chain contract code, RPC payloads), and every executor — the VM
//! witness, the proving circuit and the indexed-IR `VmExecutor` — trusts it:
//! malformed opcode arity, operand ids, input indices or state-command
//! references currently surface as panics (index-out-of-bounds, `todo!()`,
//! `unimplemented!()`, `unreachable!()`) in the middle of execution.
//!
//! [`validate_function_definition`] walks the definitions exactly the way
//! `PsyCompileResult::compile` emits them and rejects anything the
//! production layout could never contain, BEFORE any executor touches it:
//!
//! - opcode arity and the inline `const_param` conventions (`SplitBits` =
//!   `[num_bits, value_id]`; input/constant defs carry one raw word);
//! - operand ids decode to a lane/index that exists at that position
//!   (children-before-parent) and the lane is acceptable for the slot
//!   (boolean ops require the bool lane; scalar slots accept
//!   Target/U32Target/Bool; `TargetAt`'s base requires an array lane);
//! - raw input indices `< circuit_inputs.len()` and inputs-first ordering;
//! - pool occupancy: `def.index` equals the per-lane counter (append-only
//!   emission) and `def.data_type` matches the opcode's lane;
//! - constant ranges (`Constant` canonical, `ConstantU32 <= 0xffff_ffff`,
//!   `SplitBits` num_bits <= 64, `SumBits` <= 64 inputs);
//! - state-command results: single input, command index in range, command
//!   resolves at or before the def that reads it, resolution indices
//!   well-formed and non-decreasing;
//! - opcodes that no executor implements (`HashPad`,
//!   `CalculateMerkleRoot`, the deprecated `GetStateQueryResult*`) are
//!   rejected instead of aborting the process.
//!
//! Validation is structural, not semantic: a definition that passes here is
//! still subject to the runtime checks of `ops::semantics` (checked u32
//! arithmetic, casts, zero divisors) during execution.

use psy_config::network_constants::MAX_EVENT_RECORDS_PER_CALL;

use crate::dpn::ops::op_types::{
    decode_indexed_op_id, DPNBuiltInDataType, DPNIndexedVarDef, DPNOpType,
};
use crate::dpn::vm::def::DPNFunctionCircuitDefinition;

/// Goldilocks field order; `Constant` words must be canonical (`< ORDER`).
const GOLDILOCKS_ORDER: u64 = 0xFFFF_FFFF_0000_0001;

/// Why a compiled definition was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationError {
    UnsupportedOpcode { def_index: usize, op: DPNOpType },
    BadArity { def_index: usize, op: DPNOpType, got: usize },
    BadDataType { def_index: usize, op: DPNOpType, declared: DPNBuiltInDataType },
    BadPoolIndex { def_index: usize, op: DPNOpType, lane: DPNBuiltInDataType, index: usize },
    BadOperand { def_index: usize, op: DPNOpType, slot: usize, id: u64 },
    OperandLane { def_index: usize, op: DPNOpType, slot: usize, lane: DPNBuiltInDataType },
    BadConstant { def_index: usize, op: DPNOpType, value: u64 },
    BadInputIndex { def_index: usize, input_index: u64 },
    InputsNotFirst { def_index: usize, op: DPNOpType },
    BadSplitBitsNumBits { def_index: usize, num_bits: u64 },
    BadStateCommandRef { def_index: usize, op: DPNOpType, command: u64 },
    ConstantPosition { def_index: usize, op: DPNOpType, slot: usize, id: u64 },
    BadResolutionIndices,
    BadOutputId { id: u64 },
    TooManyEvents { got: usize },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::UnsupportedOpcode { def_index, op } => {
                write!(f, "def #{def_index}: {op:?} is not executable in compiled programs")
            }
            ValidationError::BadArity { def_index, op, got } => {
                write!(f, "def #{def_index}: {op:?} has {got} inputs, which the opcode never emits")
            }
            ValidationError::BadDataType { def_index, op, declared } => {
                write!(f, "def #{def_index}: {op:?} declares data type {declared:?}, which does not match the opcode's lane")
            }
            ValidationError::BadPoolIndex { def_index, op, lane, index } => {
                write!(f, "def #{def_index}: {op:?} writes {lane:?} index {index}, which is not the next pool slot (append-only emission violated)")
            }
            ValidationError::BadOperand { def_index, op, slot, id } => {
                write!(f, "def #{def_index}: {op:?} operand slot {slot} id {id:#x} does not reference an existing definition")
            }
            ValidationError::OperandLane { def_index, op, slot, lane } => {
                write!(f, "def #{def_index}: {op:?} operand slot {slot} references the {lane:?} lane, which the opcode cannot read")
            }
            ValidationError::BadConstant { def_index, op, value } => {
                write!(f, "def #{def_index}: {op:?} constant {value:#x} is out of range")
            }
            ValidationError::BadInputIndex { def_index, input_index } => {
                write!(f, "def #{def_index}: input index {input_index} is out of range")
            }
            ValidationError::InputsNotFirst { def_index, op } => {
                write!(f, "def #{def_index}: {op:?} appears after non-input definitions; inputs are emitted first")
            }
            ValidationError::BadSplitBitsNumBits { def_index, num_bits } => {
                write!(f, "def #{def_index}: SplitBits num_bits {num_bits} exceeds 64")
            }
            ValidationError::BadStateCommandRef { def_index, op, command } => {
                write!(f, "def #{def_index}: {op:?} references state command {command}, which does not resolve at or before this definition")
            }
            ValidationError::ConstantPosition { def_index, op, slot, id } => {
                write!(f, "def #{def_index}: {op:?} operand slot {slot} id {id:#x} must reference a compile-time constant def")
            }
            ValidationError::BadResolutionIndices => {
                write!(f, "state_command_resolution_indices must match state_commands, be non-decreasing and not exceed the definition count")
            }
            ValidationError::BadOutputId { id } => {
                write!(f, "output/assertion/event id {id:#x} does not reference an existing definition")
            }
            ValidationError::TooManyEvents { got } => {
                write!(f, "{got} events exceed the per-call maximum of {MAX_EVENT_RECORDS_PER_CALL}")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Per-lane occupancy counters, mirroring `PsyCompileResult`, plus the
/// compile-time constant values seen so far (needed where a consumer
/// requires a constant-0 index operand, e.g. `TargetAt` over a scalar).
#[derive(Default)]
struct Pools {
    targets: usize,
    bools: usize,
    u32s: usize,
    hashes: usize,
    hash160s: usize,
    target_arrays: usize,
    bool_arrays: usize,
    u32_arrays: usize,
    constants: std::collections::HashMap<(DPNBuiltInDataType, usize), u64>,
}

impl Pools {
    fn len_of(&self, lane: DPNBuiltInDataType) -> Option<usize> {
        match lane {
            DPNBuiltInDataType::Target => Some(self.targets),
            DPNBuiltInDataType::Bool => Some(self.bools),
            DPNBuiltInDataType::U32Target => Some(self.u32s),
            DPNBuiltInDataType::HashOut => Some(self.hashes),
            DPNBuiltInDataType::HashOut160 => Some(self.hash160s),
            DPNBuiltInDataType::TargetArray => Some(self.target_arrays),
            DPNBuiltInDataType::BoolArray => Some(self.bool_arrays),
            DPNBuiltInDataType::U32TargetArray => Some(self.u32_arrays),
            DPNBuiltInDataType::Unknown => None,
        }
    }

    fn bump(&mut self, lane: DPNBuiltInDataType) {
        match lane {
            DPNBuiltInDataType::Target => self.targets += 1,
            DPNBuiltInDataType::Bool => self.bools += 1,
            DPNBuiltInDataType::U32Target => self.u32s += 1,
            DPNBuiltInDataType::HashOut => self.hashes += 1,
            DPNBuiltInDataType::HashOut160 => self.hash160s += 1,
            DPNBuiltInDataType::TargetArray => self.target_arrays += 1,
            DPNBuiltInDataType::BoolArray => self.bool_arrays += 1,
            DPNBuiltInDataType::U32TargetArray => self.u32_arrays += 1,
            DPNBuiltInDataType::Unknown => {}
        }
    }

    fn record_constant(&mut self, lane: DPNBuiltInDataType, index: usize, value: u64) {
        self.constants.insert((lane, index), value);
    }

    /// True when `id` references any compile-time constant def.
    fn is_constant(&self, id: u64) -> bool {
        let (lane, index) = decode_indexed_op_id(id);
        self.constants.contains_key(&(lane, index))
    }

    /// True when `id` references a compile-time constant def whose value is
    /// `value` (used for the constant-0 index convention of `TargetAt`).
    fn is_constant_value(&self, id: u64, value: u64) -> bool {
        let (lane, index) = decode_indexed_op_id(id);
        self.constants.get(&(lane, index)) == Some(&value)
    }
}

/// Operand-slot lane expectations. Scalar slots accept every scalar lane
/// (cross-lane reads zero-extend / range-check at execution); boolean ops
/// resolve through the strict bool lane; `TargetAt`'s base is an array.
const SCALAR_LANES: &[DPNBuiltInDataType] =
    &[DPNBuiltInDataType::Target, DPNBuiltInDataType::U32Target, DPNBuiltInDataType::Bool];
const ARRAY_LANES: &[DPNBuiltInDataType] = &[
    DPNBuiltInDataType::TargetArray,
    DPNBuiltInDataType::BoolArray,
    DPNBuiltInDataType::U32TargetArray,
    DPNBuiltInDataType::HashOut,
];

/// Validate a compiled definition. `Ok(())` means the structure is exactly
/// something `PsyCompileResult::compile` could have emitted.
pub fn validate_function_definition(
    defn: &DPNFunctionCircuitDefinition,
) -> Result<(), ValidationError> {
    if defn.events.len() > MAX_EVENT_RECORDS_PER_CALL {
        return Err(ValidationError::TooManyEvents { got: defn.events.len() });
    }

    // State-command interleave: one resolution index per command,
    // non-decreasing, each within the definition list.
    if defn.state_command_resolution_indices.len() != defn.state_commands.len() {
        return Err(ValidationError::BadResolutionIndices);
    }
    for pair in defn.state_command_resolution_indices.windows(2) {
        if pair[0] > pair[1] {
            return Err(ValidationError::BadResolutionIndices);
        }
    }
    if defn.state_command_resolution_indices.iter().any(|&r| r > defn.definitions.len()) {
        return Err(ValidationError::BadResolutionIndices);
    }

    let num_inputs = defn.circuit_inputs.len();
    let mut pools = Pools::default();
    let mut seen_non_input = false;

    for (i, def) in defn.definitions.iter().enumerate() {
        validate_def(def, i, &pools, num_inputs, &mut seen_non_input, defn)?;
        let index = def.index;
        let lane = def.data_type;
        pools.bump(lane);
        // Track compile-time constants for the constant-0 index convention.
        match def.op_type {
            DPNOpType::Constant | DPNOpType::ConstantU32 => {
                pools.record_constant(lane, index, def.inputs[0])
            }
            DPNOpType::ConstantTrue => pools.record_constant(lane, index, 1),
            DPNOpType::ConstantFalse => pools.record_constant(lane, index, 0),
            _ => {}
        }
    }

    // Outputs, assertions and events reference completed pools.
    for &id in defn.circuit_outputs.iter() {
        check_operand_id(id, &pools, SCALAR_LANES).map_err(|_| ValidationError::BadOutputId { id })?;
    }
    for assertion in defn.assertions.iter() {
        check_operand_id(assertion.left, &pools, SCALAR_LANES)
            .map_err(|_| ValidationError::BadOutputId { id: assertion.left })?;
        check_operand_id(assertion.right, &pools, SCALAR_LANES)
            .map_err(|_| ValidationError::BadOutputId { id: assertion.right })?;
    }
    for event in defn.events.iter() {
        let ids = std::iter::once(&event.condition)
            .chain(std::iter::once(&event.checkpoint_id))
            .chain(std::iter::once(&event.user_id))
            .chain(std::iter::once(&event.contract_id))
            .chain(event.data.iter());
        for &id in ids {
            check_operand_id(id, &pools, SCALAR_LANES)
                .map_err(|_| ValidationError::BadOutputId { id })?;
        }
    }
    Ok(())
}

fn validate_def(
    def: &DPNIndexedVarDef,
    i: usize,
    pools: &Pools,
    num_inputs: usize,
    seen_non_input: &mut bool,
    defn: &DPNFunctionCircuitDefinition,
) -> Result<(), ValidationError> {
    use DPNOpType as Op;

    let op = def.op_type;

    // Lane/opcode consistency and append-only pool occupancy.
    if def.data_type != op.get_data_type() {
        return Err(ValidationError::BadDataType { def_index: i, op, declared: def.data_type });
    }
    match pools.len_of(def.data_type) {
        Some(len) if def.index == len => {}
        _ => {
            return Err(ValidationError::BadPoolIndex {
                def_index: i,
                op,
                lane: def.data_type,
                index: def.index,
            })
        }
    }

    // Opcodes with no implementation in any executor must not reach one.
    if matches!(
        op,
        Op::HashPad | Op::CalculateMerkleRoot | Op::GetStateQueryResult | Op::GetStateQueryResultSingle
    ) {
        return Err(ValidationError::UnsupportedOpcode { def_index: i, op });
    }

    // Operand slots must reference an existing def on an allowed lane.
    let check = |slot: usize, id: u64, lanes: &[DPNBuiltInDataType]| -> Result<(), ValidationError> {
        let (lane, index) = decode_indexed_op_id(id);
        match pools.len_of(lane) {
            Some(len) if index < len => {}
            _ => return Err(ValidationError::BadOperand { def_index: i, op, slot, id }),
        }
        if !lanes.contains(&lane) {
            return Err(ValidationError::OperandLane { def_index: i, op, slot, lane });
        }
        Ok(())
    };

    match op {
        // ---- inline defs: one raw word, no operand ids ----
        Op::InputTarget | Op::U32InputTarget | Op::BoolInputTarget => {
            if *seen_non_input {
                return Err(ValidationError::InputsNotFirst { def_index: i, op });
            }
            if def.inputs.len() != 1 {
                return Err(ValidationError::BadArity { def_index: i, op, got: def.inputs.len() });
            }
            if def.inputs[0] as usize >= num_inputs {
                return Err(ValidationError::BadInputIndex { def_index: i, input_index: def.inputs[0] });
            }
        }
        Op::Constant | Op::ConstantU32 => {
            if def.inputs.len() != 1 {
                return Err(ValidationError::BadArity { def_index: i, op, got: def.inputs.len() });
            }
            let max = if op == Op::Constant { GOLDILOCKS_ORDER } else { 0x1_0000_0000 };
            if def.inputs[0] >= max {
                return Err(ValidationError::BadConstant { def_index: i, op, value: def.inputs[0] });
            }
            *seen_non_input = true;
        }
        // Valueless context getters compile to `inputs = [0]`; some in-repo
        // builders emit the empty shape — accept both.
        Op::ConstantTrue
        | Op::ConstantFalse
        | Op::GetUserId
        | Op::GetContractId
        | Op::GetCallerContractId
        | Op::GetCheckpointId
        | Op::GetNonce
        | Op::GetUserPublicKeyHash
        | Op::GetSessionProofTreeRoot => {
            if def.inputs.len() > 1 {
                return Err(ValidationError::BadArity { def_index: i, op, got: def.inputs.len() });
            }
            *seen_non_input = true;
        }

        // ---- inline const_param conventions ----
        // Compiled layout: `[num_bits (raw const), value_id,
        // num_bits_const_id]` — `has_constant_param` prepends the raw
        // num_bits and the producer's `op_const(num_bits)` child is
        // retained; consumers read only inputs[0..2].
        Op::SplitBits => {
            if def.inputs.len() != 3 {
                return Err(ValidationError::BadArity { def_index: i, op, got: def.inputs.len() });
            }
            if def.inputs[0] > 64 {
                return Err(ValidationError::BadSplitBitsNumBits { def_index: i, num_bits: def.inputs[0] });
            }
            check(1, def.inputs[1], SCALAR_LANES)?;
            check(2, def.inputs[2], SCALAR_LANES)?;
            *seen_non_input = true;
        }
        Op::GetStateCommandResultHash | Op::GetStateCommandResultSingle | Op::GetStateCommandResultArray => {
            if def.inputs.len() != 1 {
                return Err(ValidationError::BadArity { def_index: i, op, got: def.inputs.len() });
            }
            let command = def.inputs[0] as usize;
            let resolves_in_time =
                command < defn.state_commands.len() && defn.state_command_resolution_indices[command] <= i;
            if !resolves_in_time {
                return Err(ValidationError::BadStateCommandRef { def_index: i, op, command: def.inputs[0] });
            }
            *seen_non_input = true;
        }

        // ---- plain operand opcodes ----
        Op::Add
        | Op::Sub
        | Op::Mul
        | Op::Div
        | Op::Mod
        | Op::ModConstantDividend
        | Op::ModConstantDivisor
        | Op::Exp
        | Op::ExpConstantPower
        | Op::ExpConstantBase
        | Op::Eq
        | Op::Lte
        | Op::Gte
        | Op::Gt
        | Op::Lt
        | Op::U32Add
        | Op::U32Sub
        | Op::U32Mul
        | Op::U32Div
        | Op::U32Mod
        | Op::U32Exp
        | Op::U32And
        | Op::U32AndConstant
        | Op::U32Or
        | Op::U32OrConstant
        | Op::U32Xor
        | Op::U32XorConstant
        | Op::U32ShiftLeft
        | Op::U32ShiftLeftConstantBitDistance
        | Op::U32ShiftLeftConstantValue
        | Op::U32ShiftRight
        | Op::U32ShiftRightConstantBitDistance
        | Op::U32ShiftRightConstantValue => {
            if def.inputs.len() != 2 {
                return Err(ValidationError::BadArity { def_index: i, op, got: def.inputs.len() });
            }
            check(0, def.inputs[0], SCALAR_LANES)?;
            check(1, def.inputs[1], SCALAR_LANES)?;
            // Constant*-variant producer invariants: the designated operand
            // must actually reference a compile-time constant def (the
            // circuit asserts that side with target_as_constant).
            let const_slot = match op {
                Op::ModConstantDivisor | Op::ExpConstantPower | Op::U32AndConstant
                | Op::U32OrConstant | Op::U32XorConstant | Op::U32ShiftLeftConstantBitDistance
                | Op::U32ShiftRightConstantBitDistance => Some(1),
                Op::ModConstantDividend | Op::ExpConstantBase | Op::U32ShiftLeftConstantValue
                | Op::U32ShiftRightConstantValue => Some(0),
                _ => None,
            };
            if let Some(slot) = const_slot {
                if !pools.is_constant(def.inputs[slot]) {
                    return Err(ValidationError::ConstantPosition {
                        def_index: i,
                        op,
                        slot,
                        id: def.inputs[slot],
                    });
                }
            }
            *seen_non_input = true;
        }
        // BoolNot resolves through the strict bool lane; the casts read any
        // scalar and enforce their domains at execution.
        Op::BoolNot => {
            if def.inputs.len() != 1 {
                return Err(ValidationError::BadArity { def_index: i, op, got: def.inputs.len() });
            }
            check(0, def.inputs[0], SCALAR_LANES)?;
            *seen_non_input = true;
        }
        Op::UnaryInverse | Op::UnaryNegative | Op::CastFelt | Op::CastU32 | Op::CastBool => {
            if def.inputs.len() != 1 {
                return Err(ValidationError::BadArity { def_index: i, op, got: def.inputs.len() });
            }
            check(0, def.inputs[0], SCALAR_LANES)?;
            *seen_non_input = true;
        }
        Op::BoolAnd | Op::BoolOr | Op::Xor | Op::Nor => {
            if def.inputs.len() != 2 {
                return Err(ValidationError::BadArity { def_index: i, op, got: def.inputs.len() });
            }
            check(0, def.inputs[0], SCALAR_LANES)?;
            check(1, def.inputs[1], SCALAR_LANES)?;
            *seen_non_input = true;
        }
        Op::Select => {
            if def.inputs.len() != 3 {
                return Err(ValidationError::BadArity { def_index: i, op, got: def.inputs.len() });
            }
            check(0, def.inputs[0], SCALAR_LANES)?;
            check(1, def.inputs[1], SCALAR_LANES)?;
            check(2, def.inputs[2], SCALAR_LANES)?;
            *seen_non_input = true;
        }
        Op::TargetAt => {
            if def.inputs.len() != 2 {
                return Err(ValidationError::BadArity { def_index: i, op, got: def.inputs.len() });
            }
            let (base_lane, _) = decode_indexed_op_id(def.inputs[0]);
            if ARRAY_LANES.contains(&base_lane) {
                // Array/hash base: dynamic index is fine.
                check(0, def.inputs[0], ARRAY_LANES)?;
                check(1, def.inputs[1], SCALAR_LANES)?;
            } else {
                // Scalar base (ABI flattening): legal only with a
                // compile-time constant-0 index — exactly what
                // `resolve_target_array_ref` asserts at execution.
                check(0, def.inputs[0], SCALAR_LANES)?;
                if !pools.is_constant_value(def.inputs[1], 0) {
                    return Err(ValidationError::BadOperand {
                        def_index: i,
                        op,
                        slot: 1,
                        id: def.inputs[1],
                    });
                }
            }
            *seen_non_input = true;
        }
        Op::SumBits => {
            if def.inputs.is_empty() || def.inputs.len() > 64 {
                return Err(ValidationError::BadArity { def_index: i, op, got: def.inputs.len() });
            }
            for (slot, &id) in def.inputs.iter().enumerate() {
                check(slot, id, SCALAR_LANES)?;
            }
            *seen_non_input = true;
        }
        Op::HashNoPad | Op::Keccak256 | Op::HashTwoToOne | Op::Secp256k1Verify => {
            let expected = match op {
                Op::HashTwoToOne => Some(8),
                Op::Secp256k1Verify => Some(36),
                _ => None, // variadic, at least one word
            };
            match expected {
                Some(n) if def.inputs.len() != n => {
                    return Err(ValidationError::BadArity { def_index: i, op, got: def.inputs.len() })
                }
                None if def.inputs.is_empty() => {
                    return Err(ValidationError::BadArity { def_index: i, op, got: 0 })
                }
                _ => {}
            }
            for (slot, &id) in def.inputs.iter().enumerate() {
                check(slot, id, SCALAR_LANES)?;
            }
            *seen_non_input = true;
        }

        // DivRem4: one scalar operand, writes a two-element
        // [quotient, remainder] target array.
        Op::DivRem4 => {
            if def.inputs.len() != 1 {
                return Err(ValidationError::BadArity { def_index: i, op, got: def.inputs.len() });
            }
            check(0, def.inputs[0], SCALAR_LANES)?;
            *seen_non_input = true;
        }

        // Rejected above, before the arity table.
        Op::HashPad
        | Op::CalculateMerkleRoot
        | Op::GetStateQueryResult
        | Op::GetStateQueryResultSingle => unreachable!("unsupported opcodes are rejected before the arity table"),
    }
    Ok(())
}

fn check_operand_id(id: u64, pools: &Pools, lanes: &[DPNBuiltInDataType]) -> Result<(), ()> {
    let (lane, index) = decode_indexed_op_id(id);
    match pools.len_of(lane) {
        Some(len) if index < len => {}
        _ => return Err(()),
    }
    if !lanes.contains(&lane) {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpn::ops::op_types::encode_indexed_op_id;

    fn target_id(i: usize) -> u64 {
        encode_indexed_op_id(DPNBuiltInDataType::Target, i)
    }

    fn def(op: DPNOpType, index: usize, inputs: Vec<u64>) -> DPNIndexedVarDef {
        DPNIndexedVarDef { data_type: op.get_data_type(), index, op_type: op, inputs }
    }

    /// [InputTarget(0), Constant(7), Add] — the minimal valid program.
    fn valid_program() -> DPNFunctionCircuitDefinition {
        DPNFunctionCircuitDefinition {
            name: "test".to_string(),
            method_id: 0,
            circuit_inputs: vec![target_id(0)],
            circuit_outputs: vec![target_id(2)],
            state_commands: vec![],
            state_command_resolution_indices: vec![],
            assertions: vec![],
            events: vec![],
            definitions: vec![
                def(DPNOpType::InputTarget, 0, vec![0]),
                def(DPNOpType::Constant, 1, vec![7]),
                def(DPNOpType::Add, 2, vec![target_id(0), target_id(1)]),
            ],
        }
    }

    fn with_defs(mut base: DPNFunctionCircuitDefinition, defs: Vec<DPNIndexedVarDef>) -> DPNFunctionCircuitDefinition {
        base.definitions = defs;
        base
    }

    #[test]
    fn accepts_the_canonical_layout() {
        assert_eq!(validate_function_definition(&valid_program()), Ok(()));
    }

    #[test]
    fn rejects_bad_arity() {
        let mut p = valid_program();
        p.definitions[2].inputs.pop();
        assert!(matches!(
            validate_function_definition(&p),
            Err(ValidationError::BadArity { def_index: 2, .. })
        ));
    }

    #[test]
    fn rejects_unsupported_opcodes() {
        // HashPad lives on the (empty) hash lane, so pool occupancy passes
        // and the unsupported-opcode check fires.
        let p = with_defs(valid_program(), vec![def(DPNOpType::HashPad, 0, vec![0])]);
        assert!(matches!(
            validate_function_definition(&p),
            Err(ValidationError::UnsupportedOpcode { def_index: 0, op: DPNOpType::HashPad })
        ));
    }

    #[test]
    fn rejects_forward_operand_references() {
        // Add references a target index that does not exist yet.
        let p = with_defs(
            valid_program(),
            vec![
                def(DPNOpType::InputTarget, 0, vec![0]),
                def(DPNOpType::Add, 1, vec![target_id(0), target_id(5)]),
            ],
        );
        assert!(matches!(
            validate_function_definition(&p),
            Err(ValidationError::BadOperand { def_index: 1, slot: 1, .. })
        ));
    }

    #[test]
    fn rejects_out_of_range_constants() {
        // ConstantU32 opens the u32 lane at index 0.
        let p = with_defs(
            valid_program(),
            vec![
                def(DPNOpType::InputTarget, 0, vec![0]),
                def(DPNOpType::ConstantU32, 0, vec![0x1_0000_0000]),
            ],
        );
        assert!(matches!(
            validate_function_definition(&p),
            Err(ValidationError::BadConstant { def_index: 1, .. })
        ));
    }

    #[test]
    fn rejects_out_of_range_input_index() {
        let mut p = valid_program();
        p.definitions[0].inputs = vec![3]; // only 1 circuit input exists
        assert!(matches!(
            validate_function_definition(&p),
            Err(ValidationError::BadInputIndex { def_index: 0, .. })
        ));
    }

    #[test]
    fn rejects_inputs_after_non_input_defs() {
        let p = with_defs(
            valid_program(),
            vec![
                def(DPNOpType::Constant, 0, vec![1]),
                def(DPNOpType::InputTarget, 1, vec![0]),
            ],
        );
        assert!(matches!(
            validate_function_definition(&p),
            Err(ValidationError::InputsNotFirst { def_index: 1, .. })
        ));
    }

    #[test]
    fn rejects_pool_index_gaps() {
        // Second Target def reuses index 0 instead of appending at 1.
        let p = with_defs(
            valid_program(),
            vec![def(DPNOpType::Constant, 0, vec![1]), def(DPNOpType::Constant, 0, vec![2])],
        );
        assert!(matches!(
            validate_function_definition(&p),
            Err(ValidationError::BadPoolIndex { def_index: 1, .. })
        ));
    }

    #[test]
    fn rejects_split_bits_above_64() {
        // Compiled layout: [num_bits, value_id, num_bits_const_id].
        let p = with_defs(
            valid_program(),
            vec![
                def(DPNOpType::InputTarget, 0, vec![0]),
                def(DPNOpType::Constant, 1, vec![65]),
                def(DPNOpType::SplitBits, 0, vec![65, target_id(0), target_id(1)]),
            ],
        );
        assert!(matches!(
            validate_function_definition(&p),
            Err(ValidationError::BadSplitBitsNumBits { def_index: 2, num_bits: 65 })
        ));
    }

    #[test]
    fn accepts_scalar_target_at_with_constant_zero_index() {
        // ABI flattening: TargetAt over a scalar base is legal only with a
        // compile-time constant-0 index.
        let p = with_defs(
            valid_program(),
            vec![
                def(DPNOpType::InputTarget, 0, vec![0]),
                def(DPNOpType::Constant, 1, vec![0]),
                def(DPNOpType::TargetAt, 2, vec![target_id(0), target_id(1)]),
            ],
        );
        assert_eq!(validate_function_definition(&p), Ok(()));

        // Non-zero constant index over a scalar base is rejected.
        let p = with_defs(
            valid_program(),
            vec![
                def(DPNOpType::InputTarget, 0, vec![0]),
                def(DPNOpType::Constant, 1, vec![3]),
                def(DPNOpType::TargetAt, 2, vec![target_id(0), target_id(1)]),
            ],
        );
        assert!(matches!(
            validate_function_definition(&p),
            Err(ValidationError::BadOperand { def_index: 2, slot: 1, .. })
        ));
    }

    #[test]
    fn rejects_bad_state_command_references() {
        let mut p = valid_program();
        p.definitions.push(def(DPNOpType::GetStateCommandResultSingle, 3, vec![0]));
        // No state commands exist at all.
        assert!(matches!(
            validate_function_definition(&p),
            Err(ValidationError::BadStateCommandRef { def_index: 3, .. })
        ));
    }

    #[test]
    fn rejects_mismatched_resolution_indices() {
        let mut p = valid_program();
        p.state_command_resolution_indices = vec![1];
        assert_eq!(validate_function_definition(&p), Err(ValidationError::BadResolutionIndices));
    }

    #[test]
    fn rejects_dangling_output_ids() {
        let mut p = valid_program();
        p.circuit_outputs = vec![target_id(99)];
        assert!(matches!(
            validate_function_definition(&p),
            Err(ValidationError::BadOutputId { .. })
        ));
    }
}
