use std::{collections::HashMap, marker::PhantomData};

use plonky2::{
    field::{extension::Extendable, secp256k1_base::Secp256K1Base, secp256k1_scalar::Secp256K1Scalar},
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use psy_client_data::config::store_config::PsyHasher;
use psy_common_circuit::{
    builder::{comparison::CircuitBuilderComparison, hash::core::CircuitBuilderHashCore},
    crypto::secp256k1::{
        ecdsa::gadgets::{
            biguint::{BigUintTarget, CircuitBuilderBiguint},
            curve::AffinePointTarget,
            ecdsa::{ECDSAPublicKeyTarget, ECDSASignatureTarget},
            nonnative::NonNativeTarget,
        },
        gadget::verify_secp_sign_opcode,
    },
    hash::base_types::hash160::Hash160Target,
    u32::{
        arithmetic_u32::{CircuitBuilderU32, U32Target},
        interleaved_u32::CircuitBuilderB32,
    },
};
use psy_crypto::signature::secp256k1::curve::secp256k1::Secp256K1;
use psy_plonky2_common_circuits::hash::keccak::keccak256_u32_words_be_abi;
use psy_vm::dpn::ops::op_types::{decode_indexed_op_id, DPNBuiltInDataType, DPNIndexedVarDef, DPNOpType};

/// Bit width passed to the felt comparison gadget. A 64-bit comparison uses
/// its two-limb path (32/32 split + range-checked limb comparison), covering
/// the full canonical Goldilocks range [0, p). Native comparisons over
/// canonical u64 are therefore in exact agreement; pinned by
/// `dpn_e2e_felt_comparisons_top_bit_operands_match_native`.
const COMPARISON_BITS: usize = 64;
pub struct SimpleDPNBuilder<F: RichField + Extendable<D>, const D: usize> {
    pub targets: Vec<Option<Target>>,
    pub target_arrays: Vec<Option<Vec<Target>>>,
    pub hashes: Vec<Option<HashOutTarget>>,
    pub hash160s: Vec<Hash160Target>,
    pub bools: Vec<Option<BoolTarget>>,
    pub bool_arrays: Vec<Option<Vec<BoolTarget>>>,
    pub u32s: Vec<Option<U32Target>>,
    pub u32_arrays: Vec<Option<Vec<U32Target>>>,
    pub user_id: Target,
    pub contract_id: Target,
    pub caller_contract_id: Target,
    pub checkpoint_id: Target,
    pub user_public_key: HashOutTarget,
    pub session_proof_tree_root: HashOutTarget,
    pub nonce: Target,
    pub inputs: Vec<Target>,
    pub constant_targets: HashMap<usize, F>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleDPNBuilder<F, D> {
    fn same_target(a: Target, b: Target) -> bool {
        a == b
    }

    pub(crate) fn set_target_at(&mut self, index: usize, value: Target, source: &str) {
        if index >= self.targets.len() {
            self.targets.resize(index + 1, None);
        }
        if let Some(existing) = self.targets[index] {
            if Self::same_target(existing, value) {
                return;
            }
            panic!("Conflicting target assignment at index {} from {}", index, source);
        }
        self.targets[index] = Some(value);
    }

    fn same_hash_target(a: &HashOutTarget, b: &HashOutTarget) -> bool {
        a.elements == b.elements
    }

    fn same_bool_target(a: BoolTarget, b: BoolTarget) -> bool {
        a.target == b.target
    }

    fn set_bool_at(&mut self, index: usize, value: BoolTarget, source: &str) {
        if index >= self.bools.len() {
            self.bools.resize(index + 1, None);
        }
        if let Some(existing) = self.bools[index] {
            if Self::same_bool_target(existing, value) {
                return;
            }
            panic!("Conflicting bool assignment at index {} from {}", index, source);
        }
        self.bools[index] = Some(value);
    }

    pub(crate) fn set_hash_at(&mut self, index: usize, value: HashOutTarget, source: &str) {
        if index >= self.hashes.len() {
            self.hashes.resize(index + 1, None);
        }
        if let Some(existing) = self.hashes[index] {
            if Self::same_hash_target(&existing, &value) {
                return;
            }
            panic!("Conflicting hash assignment at index {} from {}", index, source);
        }
        self.hashes[index] = Some(value);
    }

    fn same_u32_target_array(a: &[U32Target], b: &[U32Target]) -> bool {
        a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.0 == y.0)
    }

    fn same_u32_target(a: U32Target, b: U32Target) -> bool {
        a.0 == b.0
    }

    fn set_u32_at(&mut self, index: usize, value: U32Target, source: &str) {
        if index >= self.u32s.len() {
            self.u32s.resize(index + 1, None);
        }
        if let Some(existing) = self.u32s[index] {
            if Self::same_u32_target(existing, value) {
                return;
            }
            panic!("Conflicting u32 assignment at index {} from {}", index, source);
        }
        self.u32s[index] = Some(value);
    }

    fn set_u32_array_at(&mut self, index: usize, value: Vec<U32Target>, source: &str) {
        if index >= self.u32_arrays.len() {
            self.u32_arrays.resize(index + 1, None);
        }
        if let Some(existing) = &self.u32_arrays[index] {
            if Self::same_u32_target_array(existing, &value) {
                return;
            }
            panic!("Conflicting u32 array assignment at index {} from {}", index, source);
        }
        self.u32_arrays[index] = Some(value);
    }
    pub fn new_with_contract_ctx(
        inputs: Vec<Target>,
        user_id: Target,
        contract_id: Target,
        caller_contract_id: Target,
        checkpoint_id: Target,
        nonce: Target,
        user_public_key: HashOutTarget,
        session_proof_tree_root: HashOutTarget,
    ) -> Self {
        SimpleDPNBuilder {
            targets: Vec::new(),
            target_arrays: Vec::new(),
            hashes: Vec::new(),
            hash160s: Vec::new(),
            bools: Vec::new(),
            bool_arrays: Vec::new(),
            u32s: Vec::new(),
            u32_arrays: Vec::new(),
            user_id,
            contract_id,
            caller_contract_id,
            checkpoint_id,
            user_public_key,
            session_proof_tree_root,
            nonce,
            inputs,
            constant_targets: HashMap::new(),
        }
    }
    pub fn push_external_target(&mut self, index: usize, target: Target) {
        self.set_target_at(index, target, "external_target");
    }
    fn same_target_array(a: &[Target], b: &[Target]) -> bool {
        a == b
    }
    fn set_target_array_at(&mut self, index: usize, value: Vec<Target>, source: &str) {
        if index >= self.target_arrays.len() {
            self.target_arrays.resize(index + 1, None);
        }
        if let Some(existing) = &self.target_arrays[index] {
            if Self::same_target_array(existing, &value) {
                return;
            }
            panic!("Conflicting target array assignment at index {} from {}", index, source);
        }
        self.target_arrays[index] = Some(value);
    }
    pub fn push_external_target_array(&mut self, index: usize, target: Vec<Target>) {
        self.set_target_array_at(index, target, "external_target_array");
    }
    pub fn push_external_hash(&mut self, target: HashOutTarget) {
        let index = self.hashes.len();
        self.set_hash_at(index, target, "external_hash");
    }
    fn same_bool_target_array(a: &[BoolTarget], b: &[BoolTarget]) -> bool {
        a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.target == y.target)
    }
    fn set_bool_array_at(&mut self, index: usize, value: Vec<BoolTarget>, source: &str) {
        if index >= self.bool_arrays.len() {
            self.bool_arrays.resize(index + 1, None);
        }
        if let Some(existing) = &self.bool_arrays[index] {
            if Self::same_bool_target_array(existing, &value) {
                return;
            }
            panic!("Conflicting bool array assignment at index {} from {}", index, source);
        }
        self.bool_arrays[index] = Some(value);
    }
    pub fn resolve_bool(&self, builder: &mut CircuitBuilder<F, D>, id: u64) -> BoolTarget {
        let (t, index) = decode_indexed_op_id(id);
        match t {
            DPNBuiltInDataType::Bool => {
                assert!(index < self.bools.len(), "Invalid bool index");
                self.bools[index].expect("Unassigned bool index")
            }
            DPNBuiltInDataType::Target => {
                assert!(index < self.targets.len(), "Invalid target index");

                let b = BoolTarget::new_unsafe(self.targets[index].expect("Unassigned target index"));
                builder.assert_bool(b);
                b
            }

            DPNBuiltInDataType::U32Target => {
                assert!(index < self.u32s.len(), "Invalid u32 index");

                let b = BoolTarget::new_unsafe(self.u32s[index].expect("Unassigned u32 index").0);
                builder.assert_bool(b);
                b
            }
            _ => panic!("Invalid data type for bool"),
        }
    }
    pub fn resolve_hash(&self, id: u64) -> HashOutTarget {
        let (t, index) = decode_indexed_op_id(id);
        match t {
            DPNBuiltInDataType::HashOut => {
                assert!(index < self.hashes.len(), "Invalid hash index");
                self.hashes[index].expect("Unassigned hash index")
            }
            _ => panic!("Invalid data type for hash"),
        }
    }
    pub fn resolve_hash160(&self, id: u64) -> Hash160Target {
        let (t, index) = decode_indexed_op_id(id);
        match t {
            DPNBuiltInDataType::HashOut160 => {
                assert!(index < self.hashes.len(), "Invalid hash160 index");
                self.hash160s[index]
            }
            _ => panic!("Invalid data type for hash160"),
        }
    }
    pub fn resolve_targets_sized<const N: usize>(&self, ids: &[u64; N]) -> [Target; N] {
        core::array::from_fn(|i| self.resolve_target(ids[i]))
    }
    pub fn resolve_targets(&self, ids: &[u64]) -> Vec<Target> {
        ids.iter().map(|id| self.resolve_target(*id)).collect::<Vec<Target>>()
    }
    pub fn resolve_target(&self, id: u64) -> Target {
        let (t, index) = decode_indexed_op_id(id);
        match t {
            DPNBuiltInDataType::Bool => {
                assert!(index < self.bools.len(), "Invalid bool index");
                self.bools[index].expect("Unassigned bool index").target
            }
            DPNBuiltInDataType::Target => {
                assert!(index < self.targets.len(), "Invalid target index");
                self.targets[index].expect("Unassigned target index")
            }

            DPNBuiltInDataType::U32Target => {
                assert!(index < self.u32s.len(), "Invalid u32 index");
                self.u32s[index].expect("Unassigned u32 index").0
            }
            _ => panic!("Invalid data type for target"),
        }
    }
    pub fn resolve_u32(&self, builder: &mut CircuitBuilder<F, D>, id: u64) -> U32Target {
        let (t, index) = decode_indexed_op_id(id);
        match t {
            DPNBuiltInDataType::U32Target => {
                assert!(index < self.u32s.len(), "Invalid u32 index");

                self.u32s[index].expect("Unassigned u32 index")
            }
            DPNBuiltInDataType::Bool => {
                assert!(index < self.bools.len(), "Invalid bool index");
                U32Target(self.bools[index].expect("Unassigned bool index").target)
            }
            DPNBuiltInDataType::Target => {
                assert!(index < self.targets.len(), "Invalid target index");
                // The u32 lane must not silently truncate felt values:
                // constrain the high 32 bits to zero (same check the
                // witness executor's checked conversion performs).
                let target = self.targets[index].expect("Unassigned target index");
                let (_low, high) =
                    psy_common_circuit::builder::core::CircuitBuilderHelpersCore::split_low_high_32bits(builder, target);
                builder.assert_zero(high);
                U32Target(target)
            }
            _ => panic!("Invalid data type for U32Target"),
        }
    }
    pub fn resolve_target_array(&self, id: u64) -> Vec<Target> {
        let (t, index) = decode_indexed_op_id(id);
        match t {
            DPNBuiltInDataType::BoolArray => {
                assert!(index < self.bool_arrays.len(), "Invalid bool array index");
                self.bool_arrays[index]
                    .as_ref()
                    .expect("Unassigned bool array index")
                    .iter()
                    .map(|b| b.target)
                    .collect()
            }
            DPNBuiltInDataType::TargetArray => {
                assert!(index < self.target_arrays.len(), "Invalid target array index");
                self.target_arrays[index].as_ref().expect("Unassigned target array index").clone()
            }

            DPNBuiltInDataType::U32TargetArray => {
                assert!(index < self.u32_arrays.len(), "Invalid u32 array index");

                self.u32_arrays[index]
                    .as_ref()
                    .expect("Unassigned u32 array index")
                    .iter()
                    .map(|b| b.0)
                    .collect()
            }
            _ => panic!("Invalid data type for target array"),
        }
    }
    pub fn resolve_target_array_ref(&self, builder: &mut CircuitBuilder<F, D>, id: u64, index_id: u64) -> Target {
        let (t, index) = decode_indexed_op_id(id);
        let (_t1, index1) = decode_indexed_op_id(index_id);
        let ind_real = self.constant_targets.get(&index1).unwrap();
        match t {
            DPNBuiltInDataType::HashOut => {
                assert!(ind_real.to_canonical_u64() < 4, "Invalid index in hash");
                self.hashes[index].expect("Unassigned hash index").elements[ind_real.to_canonical_u64() as usize]
            }
            DPNBuiltInDataType::HashOut160 => {
                assert!(ind_real.to_canonical_u64() < 5, "Invalid index in hash160");
                self.hash160s[index][ind_real.to_canonical_u64() as usize].0
            }
            DPNBuiltInDataType::BoolArray => {
                assert!(index < self.bool_arrays.len(), "Invalid bool array index");
                self.bool_arrays[index].as_ref().expect("Unassigned bool array index")[ind_real.to_canonical_u64() as usize].target
            }
            DPNBuiltInDataType::TargetArray => {
                assert!(index < self.target_arrays.len(), "Invalid target array index");
                self.target_arrays[index].as_ref().expect("Unassigned target array index")[ind_real.to_canonical_u64() as usize]
            }

            DPNBuiltInDataType::U32TargetArray => {
                assert!(index < self.u32_arrays.len(), "Invalid u32 array index");
                self.u32_arrays[index].as_ref().expect("Unassigned u32 array index")[ind_real.to_canonical_u64() as usize].0
            }
            DPNBuiltInDataType::Target => {
                assert!(
                    ind_real.to_canonical_u64() == 0,
                    "Invalid index {} for scalar Target id={}",
                    ind_real.to_canonical_u64(),
                    id
                );
                self.resolve_target(id)
            }
            DPNBuiltInDataType::Bool => {
                assert!(
                    ind_real.to_canonical_u64() == 0,
                    "Invalid index {} for scalar Bool id={}",
                    ind_real.to_canonical_u64(),
                    id
                );
                self.resolve_target(id)
            }
            DPNBuiltInDataType::U32Target => {
                assert!(
                    ind_real.to_canonical_u64() == 0,
                    "Invalid index {} for scalar U32Target id={}",
                    ind_real.to_canonical_u64(),
                    id
                );
                self.resolve_u32(builder, id).0
            }
            _ => panic!("Invalid data type for target array"),
        }
    }
    pub fn resolve_bool_array(&self, id: u64) -> Vec<BoolTarget> {
        let (t, index) = decode_indexed_op_id(id);
        match t {
            DPNBuiltInDataType::BoolArray => {
                assert!(index < self.bool_arrays.len(), "Invalid bool array index");
                self.bool_arrays[index].as_ref().expect("Unassigned bool array index").clone()
            }
            _ => panic!("Invalid data type for bool array"),
        }
    }
    pub fn resolve_u32_array(&self, id: u64) -> Vec<U32Target> {
        let (t, index) = decode_indexed_op_id(id);
        match t {
            DPNBuiltInDataType::U32TargetArray => {
                assert!(index < self.u32_arrays.len(), "Invalid u32 array index");
                self.u32_arrays[index].as_ref().expect("Unassigned u32 array index").clone()
            }
            _ => panic!("Invalid data type for bool array"),
        }
    }

    pub fn process_var_def(&mut self, builder: &mut CircuitBuilder<F, D>, op: &DPNIndexedVarDef) {
        match op.op_type {
            //DPNOpType::InputTarget => todo!("this shouldn't ever get called probably"),
            DPNOpType::InputTarget => match op.data_type {
                DPNBuiltInDataType::U32TargetArray => {
                    let mut out = Vec::with_capacity(op.inputs.len());
                    for input_idx in &op.inputs {
                        let index = *input_idx as usize;
                        if index >= self.inputs.len() {
                            panic!("Invalid input index");
                        }
                        let (low, high) =
                            psy_common_circuit::builder::core::CircuitBuilderHelpersCore::split_low_high_32bits(builder, self.inputs[index]);
                        builder.assert_zero(high);
                        out.push(U32Target(low));
                    }
                    self.set_u32_array_at(op.index as usize, out, "InputTarget(U32TargetArray)");
                }
                _ => {
                    let index = op.inputs[0] as usize;
                    if index >= self.inputs.len() {
                        panic!("Invalid input index");
                    } else {
                        self.set_target_at(op.index as usize, self.inputs[index], "InputTarget(Target)");
                    }
                }
            },
            DPNOpType::Constant => {
                // Use the IR op index as the stable key. `self.targets.len()` can diverge
                // once non-Target outputs (e.g. U32 arrays / hashes) are interleaved.
                self.constant_targets.insert(op.index as usize, F::from_noncanonical_u64(op.inputs[0]));

                self.set_target_at(op.index as usize, builder.constant(F::from_noncanonical_u64(op.inputs[0])), "Constant")
            }
            DPNOpType::ConstantTrue => self.set_bool_at(op.index as usize, builder._true(), "ConstantTrue"),
            DPNOpType::ConstantFalse => self.set_bool_at(op.index as usize, builder._false(), "ConstantFalse"),
            DPNOpType::Add => {
                let left = self.resolve_target(op.inputs[0]);
                let right = self.resolve_target(op.inputs[1]);
                self.set_target_at(op.index as usize, builder.add(left, right), "Add");
            }
            DPNOpType::Sub => {
                let left = self.resolve_target(op.inputs[0]);
                let right = self.resolve_target(op.inputs[1]);
                self.set_target_at(op.index as usize, builder.sub(left, right), "Sub");
            }
            DPNOpType::Mul => {
                let left = self.resolve_target(op.inputs[0]);
                let right = self.resolve_target(op.inputs[1]);
                self.set_target_at(op.index as usize, builder.mul(left, right), "Mul");
            }
            DPNOpType::Div => {
                let left = self.resolve_target(op.inputs[0]);
                let right = self.resolve_target(op.inputs[1]);
                self.set_target_at(op.index as usize, builder.div(left, right), "Div");
            }
            DPNOpType::BoolNot => {
                let left = self.resolve_bool(builder, op.inputs[0]);
                self.set_bool_at(op.index as usize, builder.not(left), "BoolNot");
            }

            DPNOpType::BoolAnd => {
                let left = self.resolve_bool(builder, op.inputs[0]);
                let right = self.resolve_bool(builder, op.inputs[1]);
                self.set_bool_at(op.index as usize, builder.and(left, right), "BoolAnd");
            }
            DPNOpType::BoolOr => {
                let left = self.resolve_bool(builder, op.inputs[0]);
                let right = self.resolve_bool(builder, op.inputs[1]);
                self.set_bool_at(op.index as usize, builder.or(left, right), "BoolOr");
            }
            DPNOpType::Xor => {
                let left = self.resolve_bool(builder, op.inputs[0]);
                let not_left = builder.not(left);
                let right = self.resolve_bool(builder, op.inputs[1]);
                let not_right = builder.not(right);
                let left_and_not_right = builder.and(left, not_right);
                let not_left_and_right = builder.and(not_left, right);
                self.set_bool_at(op.index as usize, builder.or(left_and_not_right, not_left_and_right), "Xor");
            }
            DPNOpType::Nor => {
                let left = self.resolve_bool(builder, op.inputs[0]);
                let right = self.resolve_bool(builder, op.inputs[1]);
                let left_or_right = builder.or(left, right);
                self.set_bool_at(op.index as usize, builder.not(left_or_right), "Nor");
            }
            DPNOpType::Eq => {
                let left = self.resolve_target(op.inputs[0]);
                let right = self.resolve_target(op.inputs[1]);
                self.set_bool_at(op.index as usize, builder.is_equal(left, right), "Eq");
            }
            DPNOpType::Lte => {
                let left = self.resolve_target(op.inputs[0]);
                let right = self.resolve_target(op.inputs[1]);
                self.set_bool_at(op.index as usize, builder.is_less_than_or_equal(COMPARISON_BITS, left, right), "Lte")
            }
            DPNOpType::Gte => {
                let left = self.resolve_target(op.inputs[0]);
                let right = self.resolve_target(op.inputs[1]);
                self.set_bool_at(op.index as usize, builder.is_greater_than_or_equal(COMPARISON_BITS, left, right), "Gte")
            }
            DPNOpType::Gt => {
                let left = self.resolve_target(op.inputs[0]);
                let right = self.resolve_target(op.inputs[1]);
                self.set_bool_at(op.index as usize, builder.is_greater_than(COMPARISON_BITS, left, right), "Gt")
            }
            DPNOpType::Lt => {
                let left = self.resolve_target(op.inputs[0]);
                let right = self.resolve_target(op.inputs[1]);
                self.set_bool_at(op.index as usize, builder.is_less_than(COMPARISON_BITS, left, right), "Lt")
            }
            DPNOpType::SplitBits => {
                let target = self.resolve_target(op.inputs[1]);
                let num_bits = op.inputs[0] as usize;
                // SumBits downstream sums at most 64 inputs; keep the
                // decomposition domain identical on every path.
                assert!(num_bits <= 64, "SplitBits: num_bits must be at most 64");
                self.set_bool_array_at(op.index as usize, builder.split_le(target, num_bits), "SplitBits")
            }
            DPNOpType::SumBits => {
                assert!(op.inputs.len() <= 64, "Sumbits: can only sum at most 64 bits");
                let mut sum: Target = builder.zero();
                let mut power_of_two = builder.one();
                op.inputs.iter().for_each(|input| {
                    let bit = self.resolve_bool(builder, *input);
                    sum = builder.mul_add(bit.target, power_of_two, sum);
                    power_of_two = builder.add(power_of_two, power_of_two);
                });
                self.set_target_at(op.index as usize, sum, "SumBits");
            }
            DPNOpType::TargetAt => {
                let r = self.resolve_target_array_ref(builder, op.inputs[0], op.inputs[1]);
                if matches!(op.index, 49 | 50 | 51 | 52 | 54 | 56 | 58 | 60 | 61 | 62 | 63 | 64 | 65 | 66 | 67 | 68) {
                    tracing::info!(
                        op_index = op.index,
                        array_id = op.inputs[0],
                        index_id = op.inputs[1],
                        target = ?r,
                        "DPN TargetAt assigned"
                    );
                }
                self.set_target_at(op.index as usize, r, "TargetAt");
            }
            DPNOpType::HashNoPad => {
                let targets = self.resolve_targets(&op.inputs);
                // Isolate inputs: fresh virtual targets so each hash call's internal
                // wires are independent even when multiple HashNoPad ops share inputs.
                let fresh_targets: Vec<Target> = targets
                    .iter()
                    .map(|&t| {
                        let new_t = builder.add_virtual_target();
                        builder.connect(t, new_t);
                        new_t
                    })
                    .collect();
                let output = builder.hash_n_to_hash_no_pad::<PsyHasher>(fresh_targets);
                // Isolate outputs: prevents TargetAt(HashOut, k) from reading the raw
                // permutation output wire, avoiding cross-hash wire partition conflicts.
                let fresh_output = HashOutTarget {
                    elements: output.elements.map(|e| {
                        let new_e = builder.add_virtual_target();
                        builder.connect(e, new_e);
                        new_e
                    }),
                };
                if matches!(op.index, 0 | 1) {
                    tracing::info!(
                        op_index = op.index,
                        input_count = op.inputs.len(),
                        out0 = ?fresh_output.elements[0],
                        out1 = ?fresh_output.elements[1],
                        out2 = ?fresh_output.elements[2],
                        out3 = ?fresh_output.elements[3],
                        "DPN HashNoPad assigned"
                    );
                }
                self.set_hash_at(op.index as usize, fresh_output, "HashNoPad");
            }
            DPNOpType::HashTwoToOne => {
                assert_eq!(op.inputs.len(), 8, "HashTwoToOne requires exactly 8 inputs");
                let left = HashOutTarget {
                    elements: [
                        self.resolve_target(op.inputs[0]),
                        self.resolve_target(op.inputs[1]),
                        self.resolve_target(op.inputs[2]),
                        self.resolve_target(op.inputs[3]),
                    ],
                };
                let right = HashOutTarget {
                    elements: [
                        self.resolve_target(op.inputs[4]),
                        self.resolve_target(op.inputs[5]),
                        self.resolve_target(op.inputs[6]),
                        self.resolve_target(op.inputs[7]),
                    ],
                };
                let output = builder.hash_two_to_one::<PsyHasher>(left, right);
                self.set_hash_at(op.index as usize, output, "HashTwoToOne");
            }
            DPNOpType::Keccak256 => {
                let targets = self.resolve_targets(&op.inputs);
                let output = keccak256_u32_words_be_abi(builder, &targets);
                let output_common = output.into_iter().map(|x| U32Target(x.0)).collect::<Vec<_>>();
                tracing::info!(
                    op_index = op.index,
                    inputs = ?op.inputs,
                    out0 = ?output_common[0].0,
                    out1 = ?output_common[1].0,
                    out2 = ?output_common[2].0,
                    out3 = ?output_common[3].0,
                    out4 = ?output_common[4].0,
                    out5 = ?output_common[5].0,
                    out6 = ?output_common[6].0,
                    out7 = ?output_common[7].0,
                    "DPN Keccak256 assigned"
                );
                self.set_u32_array_at(op.index as usize, output_common, "Keccak256");
            }
            DPNOpType::HashPad => unimplemented!(),
            DPNOpType::Select => {
                let condition = self.resolve_target(op.inputs[0]);
                let zero = builder.zero();
                let is_condition_zero = builder.is_equal(condition, zero);
                let x = self.resolve_target(op.inputs[1]);
                let y = self.resolve_target(op.inputs[2]);

                // if condition != 0, then { x } else { y }
                // this is the same as: if condition == 0 then { y } else { x }
                self.set_target_at(op.index as usize, builder.select(is_condition_zero, y, x), "Select");
            }
            DPNOpType::Exp => {
                let left = self.resolve_target(op.inputs[0]);
                let right = self.resolve_target(op.inputs[1]);
                self.set_target_at(op.index as usize, builder.exp(left, right, 64), "Exp")
            }
            // The Constant* variants carry their constant as a regular
            // felt-lane Constant input (materialized via builder.constant,
            // so target_as_constant sees it) — the same input convention as
            // every other felt op. The old arms read the constant through
            // resolve_u32, the u32 lane, which cannot see a felt constant;
            // the Base arm also read inputs[1] twice and never inputs[0].
            DPNOpType::ExpConstantPower => {
                let left = self.resolve_target(op.inputs[0]);
                let right_value = builder
                    .target_as_constant(self.resolve_target(op.inputs[1]))
                    .expect("ExpConstantPower right must be constant")
                    .to_canonical_u64();

                self.set_target_at(op.index as usize, builder.exp_u64(left, right_value as u64), "ExpConstantPower")
            }
            DPNOpType::ExpConstantBase => {
                let base_value = builder
                    .target_as_constant(self.resolve_target(op.inputs[0]))
                    .expect("ExpConstantBase base must be constant");
                let exponent_bits = builder.split_le(self.resolve_target(op.inputs[1]), 64);
                self.set_target_at(op.index as usize, builder.exp_from_bits_const_base(base_value, exponent_bits), "ExpConstantBase")
            }
            DPNOpType::Mod | DPNOpType::ModConstantDivisor | DPNOpType::ModConstantDividend => {
                let left = self.resolve_target(op.inputs[0]);
                let right = self.resolve_target(op.inputs[1]);
                builder.assert_non_zero(right);

                let (left_low, left_high) = psy_common_circuit::builder::core::CircuitBuilderHelpersCore::split_low_high_32bits(builder, left);
                let (right_low, right_high) = psy_common_circuit::builder::core::CircuitBuilderHelpersCore::split_low_high_32bits(builder, right);
                let left_biguint = BigUintTarget {
                    limbs: vec![U32Target(left_low), U32Target(left_high)],
                };
                let right_biguint = BigUintTarget {
                    limbs: vec![U32Target(right_low), U32Target(right_high)],
                };
                let (_div_biguint, rem_biguint) = builder.div_rem_biguint(&left_biguint, &right_biguint);
                assert!(rem_biguint.limbs.len() == 2, "Felt Mod should return two limb");
                let twopow32 = psy_common_circuit::builder::core::CircuitBuilderHelpersCore::constant_u64(builder, 0x100000000);
                let res = builder.mul_add(rem_biguint.limbs[1].0, twopow32, rem_biguint.limbs[0].0);
                self.set_target_at(op.index as usize, res, "Mod");
            }
            DPNOpType::DivRem4 => {
                let target = self.resolve_target(op.inputs[0]);
                let (low, high) = builder.split_low_high(target, 2, 64);
                self.set_target_array_at(op.index as usize, vec![high, low], "DivRem4");
            }
            DPNOpType::CastU32 => {
                let target = self.resolve_target(op.inputs[0]);
                let (low, high) = psy_common_circuit::builder::core::CircuitBuilderHelpersCore::split_low_high_32bits(builder, target);
                builder.assert_zero(high);
                self.set_u32_at(op.index as usize, U32Target(low), "CastU32");
            }
            // The Constant* variants carry their constant as a regular
            // ConstantU32 child input (node-ref layout), the same input
            // convention as every other u32 op — like the ExpConstant* arms
            // above. The old arms decoded the referenced node's register
            // index out of the input id and used it as the constant value.
            DPNOpType::U32And | DPNOpType::U32AndConstant => {
                let left = self.resolve_u32(builder, op.inputs[0]);
                let right = self.resolve_u32(builder, op.inputs[1]);
                self.set_u32_at(op.index as usize, builder.and_u32(left, right), "U32And");
            }
            DPNOpType::U32Or | DPNOpType::U32OrConstant => {
                let left = self.resolve_u32(builder, op.inputs[0]);
                let right = self.resolve_u32(builder, op.inputs[1]);
                let neg_left = builder.not_u32(left);
                let neg_right = builder.not_u32(right);
                let neg_left_or_right = builder.and_u32(neg_left, neg_right);
                self.set_u32_at(op.index as usize, builder.not_u32(neg_left_or_right), "U32Or");
            }
            DPNOpType::U32Xor | DPNOpType::U32XorConstant => {
                let left = self.resolve_u32(builder, op.inputs[0]);
                let right = self.resolve_u32(builder, op.inputs[1]);
                self.set_u32_at(op.index as usize, builder.xor_u32(left, right), "U32Xor");
            }
            DPNOpType::U32ShiftLeft => {
                let left = self.resolve_u32(builder, op.inputs[0]);
                let right = self.resolve_u32(builder, op.inputs[1]);
                // Clamp dynamic distances >= 32 to the zero-result case
                // first (like U32ShiftRight below): low32(2^d mod p) is not
                // zero for large d, so the unclamped multiplier diverged
                // from native u32 shift semantics. With right_normal == 32,
                // low32(2^32) == 0 and the product is zero; below 32 the
                // multiplier is exact and the low limb is the truncating
                // u32 shift.
                let thirty_two = builder.constant_u32(32);
                let zero = builder.constant_u32(0);
                let two = builder.two();
                let (_right_exp, right_borrow) = builder.sub_u32(thirty_two, right, zero);
                let is_right_borrow_zero = builder.is_equal(right_borrow.0, zero.0);
                let right_normal = builder.select(is_right_borrow_zero, right.0, thirty_two.0);
                let power_of_two = builder.exp(two, right_normal, 6);
                let (power_of_two_low, _power_of_two_heigh) =
                    psy_common_circuit::builder::core::CircuitBuilderHelpersCore::split_low_high_32bits(builder, power_of_two);
                self.set_u32_at(op.index as usize, builder.mul_u32(left, U32Target(power_of_two_low)).0, "U32ShiftLeft");
            }
            DPNOpType::U32ShiftLeftConstantBitDistance => {
                let left = self.resolve_u32(builder, op.inputs[0]);
                let right = self.resolve_u32(builder, op.inputs[1]);
                    let right_value = builder
                        .target_as_constant(right.0)
                    .expect("U32ShiftLeftConstantBitDistance right must be constant")
                    .to_canonical_u64();

                if right_value >= 32 {
                    self.set_u32_at(op.index as usize, builder.constant_u32(0), "U32ShiftLeftConstantBitDistanceZero");
                } else {
                    self.set_u32_at(
                        op.index as usize,
                        builder.lsh_u32(left, right_value as u8),
                        "U32ShiftLeftConstantBitDistance",
                    );
                }
            }
            DPNOpType::U32ShiftLeftConstantValue => {
                let left = self.resolve_u32(builder, op.inputs[0]);
                let left_const = self.resolve_u32(builder, op.inputs[0]);
                    let _left_value = builder
                        .target_as_constant(left_const.0)
                    .expect("U32ShiftLeftConstantValue left must be constant")
                    .to_canonical_u64();
                let right = self.resolve_u32(builder, op.inputs[1]);
                // Same dynamic-distance clamp as U32ShiftLeft: the value is
                // constant, the distance is not.
                let thirty_two = builder.constant_u32(32);
                let zero = builder.constant_u32(0);
                let two = builder.two();
                let (_right_exp, right_borrow) = builder.sub_u32(thirty_two, right, zero);
                let is_right_borrow_zero = builder.is_equal(right_borrow.0, zero.0);
                let right_normal = builder.select(is_right_borrow_zero, right.0, thirty_two.0);
                let power_of_two = builder.exp(two, right_normal, 6);
                let (power_of_two_low, _power_of_two_heigh) =
                    psy_common_circuit::builder::core::CircuitBuilderHelpersCore::split_low_high_32bits(builder, power_of_two);
                self.set_u32_at(
                    op.index as usize,
                    builder.mul_u32(left, U32Target(power_of_two_low)).0,
                    "U32ShiftLeftConstantValue",
                );
            }
            DPNOpType::U32ShiftRight => {
                let left = self.resolve_u32(builder, op.inputs[0]);
                let right = self.resolve_u32(builder, op.inputs[1]);

                let thirty_two = builder.constant_u32(32);
                let zero = builder.constant_u32(0);
                let two = builder.two();
                let (_right_exp, right_borrow) = builder.sub_u32(thirty_two, right, zero);
                let is_right_borrow_zero = builder.is_equal(right_borrow.0, zero.0);

                let right_normal = builder.select(is_right_borrow_zero, right.0, thirty_two.0);

                let power_of_two = builder.exp(two, right_normal, 6);
                let (power_of_two_low, power_of_two_heigh) =
                    psy_common_circuit::builder::core::CircuitBuilderHelpersCore::split_low_high_32bits(builder, power_of_two);

                let left_biguint = BigUintTarget { limbs: vec![left] };
                let right_biguint = BigUintTarget {
                    limbs: vec![U32Target(power_of_two_low), U32Target(power_of_two_heigh)],
                };
                let (div_biguint, _rem_biguint) = builder.div_rem_biguint(&left_biguint, &right_biguint);
                // assert!(rem_biguint.limbs.len() == 1);

                self.set_u32_at(op.index as usize, div_biguint.limbs[0], "U32ShiftRight");
            }
            DPNOpType::U32ShiftRightConstantBitDistance => {
                let left = self.resolve_u32(builder, op.inputs[0]);
                let right = self.resolve_u32(builder, op.inputs[1]);
                    let right_value = builder
                        .target_as_constant(right.0)
                    .expect("U32ShiftRightConstantBitDistance right must be constant")
                    .to_canonical_u64();
                if right_value > 0xffffffffu64 {
                    panic!("U32ShiftRightConstantBitDistance right must be less than U32_MAX");
                }
                if right_value >= 32 {
                    self.set_u32_at(op.index as usize, builder.constant_u32(0), "U32ShiftRightConstantBitDistanceZero");
                } else {
                    self.set_u32_at(
                        op.index as usize,
                        builder.rsh_u32(left, right_value as u8),
                        "U32ShiftRightConstantBitDistance",
                    );
                }
            }
            DPNOpType::U32ShiftRightConstantValue => {
                let left = self.resolve_u32(builder, op.inputs[0]);
                let right = self.resolve_u32(builder, op.inputs[1]);
                let left_const = self.resolve_u32(builder, op.inputs[0]);
                    let left_value = builder
                        .target_as_constant(left_const.0)
                    .expect("U32ShiftRightConstantValue left must be constant")
                    .to_canonical_u64();
                if left_value > 0xffffffffu64 {
                    panic!("U32ShiftRightConstantValue left must be less than U32_MAX");
                }
                let thirty_two = builder.constant_u32(32);
                let zero = builder.constant_u32(0);
                let two = builder.two();
                let (_right_exp, right_borrow) = builder.sub_u32(thirty_two, right, zero);
                let is_right_borrow_zero = builder.is_equal(right_borrow.0, zero.0);

                let right_normal = builder.select(is_right_borrow_zero, right.0, thirty_two.0);

                let power_of_two = builder.exp(two, right_normal, 6);
                let (power_of_two_low, power_of_two_heigh) =
                    psy_common_circuit::builder::core::CircuitBuilderHelpersCore::split_low_high_32bits(builder, power_of_two);

                let left_biguint = BigUintTarget { limbs: vec![left] };
                let right_biguint = BigUintTarget {
                    limbs: vec![U32Target(power_of_two_low), U32Target(power_of_two_heigh)],
                };
                let (div_biguint, _rem_biguint) = builder.div_rem_biguint(&left_biguint, &right_biguint);
                // assert!(rem_biguint.limbs.len() == 1);

                self.set_u32_at(op.index as usize, div_biguint.limbs[0], "U32ShiftRightConstantValue");
            }
            DPNOpType::CalculateMerkleRoot => unimplemented!(),
            DPNOpType::GetUserId => self.set_target_at(op.index as usize, self.user_id, "GetUserId"),
            DPNOpType::GetContractId => self.set_target_at(op.index as usize, self.contract_id, "GetContractId"),
            DPNOpType::GetCallerContractId => self.set_target_at(op.index as usize, self.caller_contract_id, "GetCallerContractId"),
            DPNOpType::GetCheckpointId => self.set_target_at(op.index as usize, self.checkpoint_id, "GetCheckpointId"),
            DPNOpType::GetNonce => self.set_target_at(op.index as usize, self.nonce, "GetNonce"),
            DPNOpType::GetUserPublicKeyHash => self.set_hash_at(op.index as usize, self.user_public_key, "GetUserPublicKeyHash"),
            DPNOpType::GetSessionProofTreeRoot => self.set_hash_at(op.index as usize, self.session_proof_tree_root, "GetSessionProofTreeRoot"),

            // GetStateQueryResult is deprecated, use GetStateCommandResult instead
            DPNOpType::GetStateQueryResult => unimplemented!("deprecated"),
            DPNOpType::GetStateQueryResultSingle => unimplemented!("deprecated"),

            DPNOpType::GetStateCommandResultHash => unreachable!(),
            DPNOpType::GetStateCommandResultSingle => unreachable!(),
            DPNOpType::GetStateCommandResultArray => unreachable!(),
            DPNOpType::UnaryInverse => {
                let target = self.resolve_target(op.inputs[0]);
                builder.assert_non_zero(target);
                self.set_target_at(op.index as usize, builder.inverse(target), "UnaryInverse");
            }
            DPNOpType::UnaryNegative => {
                let target = self.resolve_target(op.inputs[0]);
                self.set_target_at(op.index as usize, builder.neg(target), "UnaryNegative");
            }
            DPNOpType::U32InputTarget => {
                let index = op.inputs[0] as usize;
                if index >= self.inputs.len() {
                    panic!("Invalid input index");
                } else {
                    let (low, high) =
                        psy_common_circuit::builder::core::CircuitBuilderHelpersCore::split_low_high_32bits(builder, self.inputs[index]);
                    builder.assert_zero(high);
                    self.set_u32_at(op.index as usize, U32Target(low), "U32InputTarget");
                }
            }
            DPNOpType::ConstantU32 => {
                assert!(op.inputs[0] <= 0xffffffffu64, "Invalid constant u32");
                let target = builder.constant_u32(op.inputs[0] as u32);
                self.set_u32_at(op.index as usize, target, "ConstantU32");
            }
            DPNOpType::U32Add => {
                let left = self.resolve_u32(builder, op.inputs[0]);
                let right = self.resolve_u32(builder, op.inputs[1]);
                let (low, high) = builder.add_u32(left, right);
                builder.assert_zero(high.0);
                self.set_u32_at(op.index as usize, low, "U32Add");
            }
            DPNOpType::U32Sub => {
                let left = self.resolve_u32(builder, op.inputs[0]);
                let right = self.resolve_u32(builder, op.inputs[1]);
                let zero = builder.zero_u32();
                let (low, high) = builder.sub_u32(left, right, zero);
                builder.assert_zero(high.0);
                self.set_u32_at(op.index as usize, low, "U32Sub");
            }
            DPNOpType::U32Mul => {
                let left = self.resolve_u32(builder, op.inputs[0]);
                let right = self.resolve_u32(builder, op.inputs[1]);
                let (low, high) = builder.mul_u32(left, right);
                builder.assert_zero(high.0);
                self.set_u32_at(op.index as usize, low, "U32Mul");
            }
            DPNOpType::U32Div => {
                let left = self.resolve_u32(builder, op.inputs[0]);
                let right = self.resolve_u32(builder, op.inputs[1]);

                let left_biguint = BigUintTarget { limbs: vec![left] };
                let right_biguint = BigUintTarget { limbs: vec![right] };
                let div_biguint = builder.div_biguint(&left_biguint, &right_biguint);

                assert!(div_biguint.limbs.len() == 1, "U32Div should only return one limb");

                let div = div_biguint.limbs[0];
                self.set_u32_at(op.index as usize, div, "U32Div");
            }
            DPNOpType::CastFelt => {
                let target = self.resolve_target(op.inputs[0]);
                self.set_target_at(op.index as usize, target, "CastFelt");
            }
            DPNOpType::CastBool => {
                let target = self.resolve_target(op.inputs[0]);
                let bool_target = BoolTarget::new_unsafe(target);
                builder.assert_bool(bool_target);
                self.set_bool_at(op.index as usize, bool_target, "CastBool");
            }
            DPNOpType::BoolInputTarget => {
                let index = op.inputs[0] as usize;
                if index >= self.inputs.len() {
                    panic!("Invalid input index");
                }
                let bool_target = BoolTarget::new_unsafe(self.inputs[index]);
                builder.assert_bool(bool_target);
                self.set_bool_at(op.index as usize, bool_target, "BoolInputTarget");
            }
            DPNOpType::U32Mod => {
                let left = self.resolve_u32(builder, op.inputs[0]);
                let right = self.resolve_u32(builder, op.inputs[1]);

                let left_biguint = BigUintTarget { limbs: vec![left] };
                let right_biguint = BigUintTarget { limbs: vec![right] };
                let (_div_biguint, rem_biguint) = builder.div_rem_biguint(&left_biguint, &right_biguint);

                assert!(rem_biguint.limbs.len() == 1, "U32 Mod should only return one limb");

                let div = rem_biguint.limbs[0];
                self.set_u32_at(op.index as usize, div, "U32Mod");
            }
            DPNOpType::U32Exp => {
                let left = self.resolve_u32(builder, op.inputs[0]);
                let right = self.resolve_u32(builder, op.inputs[1]);
                let res = builder.exp(left.0, right.0, 32);
                let (low, high) = psy_common_circuit::builder::core::CircuitBuilderHelpersCore::split_low_high_32bits(builder, res);
                builder.assert_zero(high);
                self.set_u32_at(op.index as usize, U32Target(low), "U32Exp");
            }
            DPNOpType::Secp256k1Verify => {
                type CURVE = Secp256K1;
                assert!(op.inputs.len() == 36, "Secp256k1Verify op must have 36 inputs");
                let msg_u32_targets = op.inputs[32..36]
                    .iter()
                    .flat_map(|id| {
                        let u64_target = self.resolve_target(*id);
                        let (_low, _high) = psy_common_circuit::builder::core::CircuitBuilderHelpersCore::split_low_high_32bits(builder, u64_target);
                        vec![U32Target(_low), U32Target(_high)]
                    })
                    .collect::<Vec<_>>();

                let msg_target = NonNativeTarget::<Secp256K1Scalar> {
                    value: BigUintTarget {
                        limbs: msg_u32_targets.to_vec(),
                    },
                    _phantom: PhantomData,
                };

                let resolve_words = |builder: &mut CircuitBuilder<F, D>, ids: &[u64]| -> Vec<U32Target> {
                    ids.iter().map(|id| self.resolve_u32(builder, *id)).collect()
                };
                let pk_x_u32_target = resolve_words(builder, &op.inputs[0..8]);
                let pk_x_target = NonNativeTarget::<Secp256K1Base> {
                    value: BigUintTarget {
                        limbs: pk_x_u32_target.to_vec(),
                    },
                    _phantom: PhantomData,
                };
                let pk_y_u32_target = resolve_words(builder, &op.inputs[8..16]);
                let pk_y_target = NonNativeTarget::<Secp256K1Base> {
                    value: BigUintTarget {
                        limbs: pk_y_u32_target.to_vec(),
                    },
                    _phantom: PhantomData,
                };
                let public_key_target = ECDSAPublicKeyTarget::<CURVE>(AffinePointTarget {
                    x: pk_x_target,
                    y: pk_y_target,
                });
                let r_u32_target = resolve_words(builder, &op.inputs[16..24]);
                let r = NonNativeTarget::<Secp256K1Scalar> {
                    value: BigUintTarget {
                        limbs: r_u32_target.to_vec(),
                    },
                    _phantom: PhantomData,
                };
                let s_u32_target = resolve_words(builder, &op.inputs[24..32]);
                let s = NonNativeTarget::<Secp256K1Scalar> {
                    value: BigUintTarget {
                        limbs: s_u32_target.to_vec(),
                    },
                    _phantom: PhantomData,
                };

                let signature_target = ECDSASignatureTarget::<Secp256K1> { r: r, s: s };

                self.set_bool_at(
                    op.index as usize,
                    verify_secp_sign_opcode::<F, D>(builder, &msg_target, &signature_target, &public_key_target),
                    "Secp256k1Verify",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
        hash::hash_types::HashOutTarget,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };
    use psy_client_data::config::store_config::PsyHasher;
    use psy_vm::dpn::ops::op_types::{encode_indexed_op_id, DPNBuiltInDataType};

    use super::*;

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    fn dummy_hash(builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        HashOutTarget {
            elements: [
                builder.add_virtual_target(),
                builder.add_virtual_target(),
                builder.add_virtual_target(),
                builder.add_virtual_target(),
            ],
        }
    }

    fn new_test_builder(builder: &mut CircuitBuilder<F, D>) -> SimpleDPNBuilder<F, D> {
        SimpleDPNBuilder::new_with_contract_ctx(
            Vec::new(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            dummy_hash(builder),
            dummy_hash(builder),
        )
    }

    #[test]
    fn sparse_target_indices_resolve_by_declared_index() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut executor = new_test_builder(&mut builder);

        let t0 = builder.add_virtual_target();
        let t2 = builder.add_virtual_target();

        executor.push_external_target(0, t0);
        executor.push_external_target(2, t2);

        assert_eq!(executor.resolve_target(encode_indexed_op_id(DPNBuiltInDataType::Target, 0)), t0);
        assert_eq!(executor.resolve_target(encode_indexed_op_id(DPNBuiltInDataType::Target, 2)), t2);
        assert_eq!(executor.targets.len(), 3);
        assert_eq!(executor.targets[1], None);
    }

    #[test]
    fn sparse_hash_indices_support_target_at_reads() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut executor = new_test_builder(&mut builder);

        let hash = HashOutTarget {
            elements: [
                builder.add_virtual_target(),
                builder.add_virtual_target(),
                builder.add_virtual_target(),
                builder.add_virtual_target(),
            ],
        };

        executor.set_hash_at(7, hash, "test");
        executor.constant_targets.insert(11, F::from_canonical_u64(2));
        let resolved = executor.resolve_target_array_ref(
            &mut builder,
            encode_indexed_op_id(DPNBuiltInDataType::HashOut, 7),
            encode_indexed_op_id(DPNBuiltInDataType::Target, 11),
        );

        assert_eq!(resolved, hash.elements[2]);
        assert_eq!(executor.hashes.len(), 8);
        assert_eq!(executor.hashes[0], None);
        assert_eq!(executor.hashes[6], None);
    }

    #[test]
    fn poseidon_hash_no_pad_two_calls_prove() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let inputs_a = (0..35).map(|_| builder.add_virtual_target()).collect::<Vec<_>>();
        let inputs_b = (0..8).map(|_| builder.add_virtual_target()).collect::<Vec<_>>();

        let hash_a = builder.hash_n_to_hash_no_pad::<PsyHasher>(inputs_a.clone());
        let hash_b = builder.hash_n_to_hash_no_pad::<PsyHasher>(inputs_b.clone());

        for target in hash_a.elements.into_iter().chain(hash_b.elements) {
            builder.register_public_input(target);
        }

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        for (i, target) in inputs_a.into_iter().chain(inputs_b).enumerate() {
            pw.set_target(target, F::from_canonical_u64((i + 1) as u64)).unwrap();
        }

        let proof = data.prove(pw).expect("two plain hash_no_pad calls should prove");
        data.verify(proof).expect("two plain hash_no_pad calls should verify");
    }

    #[test]
    fn dpn_hash_no_pad_two_ops_prove() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut executor = new_test_builder(&mut builder);

        let mut witness_targets = Vec::new();
        for index in 0..43usize {
            let target = builder.add_virtual_target();
            executor.push_external_target(index, target);
            witness_targets.push(target);
        }

        let op_a = DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::HashOut,
            index: 0,
            op_type: DPNOpType::HashNoPad,
            inputs: (0..35).map(|i| encode_indexed_op_id(DPNBuiltInDataType::Target, i)).collect(),
        };
        let op_b = DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::HashOut,
            index: 1,
            op_type: DPNOpType::HashNoPad,
            inputs: (35..43).map(|i| encode_indexed_op_id(DPNBuiltInDataType::Target, i)).collect(),
        };

        executor.process_var_def(&mut builder, &op_a);
        executor.process_var_def(&mut builder, &op_b);

        let hash_a = executor.resolve_hash(encode_indexed_op_id(DPNBuiltInDataType::HashOut, 0));
        let hash_b = executor.resolve_hash(encode_indexed_op_id(DPNBuiltInDataType::HashOut, 1));
        for target in hash_a.elements.into_iter().chain(hash_b.elements) {
            builder.register_public_input(target);
        }

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        for (i, target) in witness_targets.into_iter().enumerate() {
            pw.set_target(target, F::from_canonical_u64((i + 1) as u64)).unwrap();
        }

        let proof = data.prove(pw).expect("two DPN HashNoPad ops should prove");
        data.verify(proof).expect("two DPN HashNoPad ops should verify");
    }

    #[test]
    fn poseidon_hash_no_pad_two_calls_with_shared_inputs_prove() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let unique_a = (0..27).map(|_| builder.add_virtual_target()).collect::<Vec<_>>();
        let shared = (0..8).map(|_| builder.add_virtual_target()).collect::<Vec<_>>();
        let inputs_a = unique_a.iter().copied().chain(shared.iter().copied()).collect::<Vec<_>>();
        let inputs_b = shared.clone();

        let hash_a = builder.hash_n_to_hash_no_pad::<PsyHasher>(inputs_a.clone());
        let hash_b = builder.hash_n_to_hash_no_pad::<PsyHasher>(inputs_b.clone());

        for target in hash_a.elements.into_iter().chain(hash_b.elements) {
            builder.register_public_input(target);
        }

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        for (i, target) in unique_a.into_iter().chain(shared.into_iter()).enumerate() {
            pw.set_target(target, F::from_canonical_u64((i + 1) as u64)).unwrap();
        }

        let proof = data.prove(pw).expect("two plain hash_no_pad calls with shared inputs should prove");
        data.verify(proof).expect("two plain hash_no_pad calls with shared inputs should verify");
    }

    #[test]
    fn dpn_hash_no_pad_two_ops_with_shared_inputs_prove() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut executor = new_test_builder(&mut builder);

        let mut unique_targets = Vec::new();
        for index in 0..27usize {
            let target = builder.add_virtual_target();
            executor.push_external_target(index, target);
            unique_targets.push(target);
        }

        let mut shared_targets = Vec::new();
        for index in 27..35usize {
            let target = builder.add_virtual_target();
            executor.push_external_target(index, target);
            shared_targets.push(target);
        }

        let op_a = DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::HashOut,
            index: 0,
            op_type: DPNOpType::HashNoPad,
            inputs: (0..35).map(|i| encode_indexed_op_id(DPNBuiltInDataType::Target, i)).collect(),
        };
        let op_b = DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::HashOut,
            index: 1,
            op_type: DPNOpType::HashNoPad,
            inputs: (27..35).map(|i| encode_indexed_op_id(DPNBuiltInDataType::Target, i)).collect(),
        };

        executor.process_var_def(&mut builder, &op_a);
        executor.process_var_def(&mut builder, &op_b);

        let hash_a = executor.resolve_hash(encode_indexed_op_id(DPNBuiltInDataType::HashOut, 0));
        let hash_b = executor.resolve_hash(encode_indexed_op_id(DPNBuiltInDataType::HashOut, 1));
        for target in hash_a.elements.into_iter().chain(hash_b.elements) {
            builder.register_public_input(target);
        }

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        for (i, target) in unique_targets.into_iter().chain(shared_targets.into_iter()).enumerate() {
            pw.set_target(target, F::from_canonical_u64((i + 1) as u64)).unwrap();
        }

        let proof = data.prove(pw).expect("two DPN HashNoPad ops with shared inputs should prove");
        data.verify(proof).expect("two DPN HashNoPad ops with shared inputs should verify");
    }

    // Two full secp256k1 nonnative proofs, ~4 min in debug.
    #[test]
    fn dpn_secp256k1_verify_op_matches_native_signature() {
        use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
        use psy_crypto::signature::secp256k1::curve::{
            curve_types::{Curve, CurveScalar},
            ecdsa::{sign_message, ECDSAPublicKey, ECDSASecretKey},
        };

        // Deterministic vector signed with the native psy_crypto
        // implementation. The same expectations (valid -> 1, malformed pk ->
        // 0, no abort) are pinned on the VM path by
        // psy_vm::dpn::vm::exec::tests::secp256k1_verify_matches_native_k256;
        // this test pins the circuit layer so the three stay consistent —
        // the gadget computes curve_is_valid(pk) && r == x, so an off-curve
        // point proves fine and yields false (it is not an unsatisfiability).
        let sk = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::from_noncanonical_u64(0x4242_4242_4242_4242));
        let msg = Secp256K1Scalar::from_noncanonical_u64(0x0102_0304_0506_0708);
        let sig = sign_message(msg, sk);
        let pk = ECDSAPublicKey((CurveScalar(sk.0) * Secp256K1::GENERATOR_PROJECTIVE).to_affine());

        // [u64; 4] little-endian limbs -> u32 limbs, least significant first,
        // the layout the Secp256k1Verify arm's BigUintTargets expect.
        let limbs32 = |a: &[u64; 4]| -> Vec<u64> {
            a.iter().flat_map(|w| [w & 0xffffffff, w >> 32]).collect()
        };

        // 36 DPN inputs: pk x[8] || pk y[8] || r[8] || s[8] as u32 words
        // (U32InputTarget lane), then msg as 4 full felts (InputTarget lane).
        let mut words: Vec<u64> = Vec::new();
        words.extend_from_slice(&limbs32(&pk.0.x.0));
        words.extend_from_slice(&limbs32(&pk.0.y.0));
        words.extend_from_slice(&limbs32(&sig.r.0));
        words.extend_from_slice(&limbs32(&sig.s.0));

        // Same config as the production CFC circuit (circuits/cfc.rs);
        // standard_recursion_config cannot fit the secp gadget's
        // U32RangeCheckGate (136 wires vs 135).
        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let input_targets: Vec<Target> = (0..36).map(|_| builder.add_virtual_target()).collect();
        let mut executor = SimpleDPNBuilder::new_with_contract_ctx(
            input_targets.clone(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            dummy_hash(&mut builder),
            dummy_hash(&mut builder),
        );

        for i in 0..32usize {
            executor.process_var_def(
                &mut builder,
                &DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::U32Target,
                    index: i,
                    op_type: DPNOpType::U32InputTarget,
                    inputs: vec![i as u64],
                },
            );
        }
        for i in 0..4usize {
            executor.process_var_def(
                &mut builder,
                &DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Target,
                    index: i,
                    op_type: DPNOpType::InputTarget,
                    inputs: vec![(32 + i) as u64],
                },
            );
        }
        let mut op_inputs: Vec<u64> = (0..32).map(|i| encode_indexed_op_id(DPNBuiltInDataType::U32Target, i)).collect();
        op_inputs.extend((0..4).map(|i| encode_indexed_op_id(DPNBuiltInDataType::Target, i)));
        executor.process_var_def(
            &mut builder,
            &DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::Bool,
                index: 0,
                op_type: DPNOpType::Secp256k1Verify,
                inputs: op_inputs,
            },
        );
        let result = executor.resolve_bool(&mut builder, encode_indexed_op_id(DPNBuiltInDataType::Bool, 0));
        builder.register_public_input(result.target);

        let data = builder.build::<C>();

        let set_witness = |pw: &mut PartialWitness<F>, words: &[u64], msg_words: &[u64; 4]| {
            for (target, word) in input_targets.iter().zip(words.iter().chain(msg_words.iter())) {
                pw.set_target(*target, F::from_canonical_u64(*word)).unwrap();
            }
        };

        // Valid vector -> 1.
        let mut pw = PartialWitness::new();
        set_witness(&mut pw, &words, &msg.0);
        let proof = data.prove(pw).expect("valid DPN Secp256k1Verify must prove");
        data.verify(proof.clone()).expect("valid DPN Secp256k1Verify must verify");
        assert_eq!(proof.public_inputs[0], F::ONE, "valid signature must verify to 1");

        // Malformed pk (y top limb corrupted -> off-curve) -> 0, and the
        // witness is still satisfiable: the gadget outputs false instead of
        // making the circuit unsatisfiable.
        let mut bad_pk = words.clone();
        bad_pk[15] ^= 1;
        let mut pw = PartialWitness::new();
        set_witness(&mut pw, &bad_pk, &msg.0);
        let proof = data.prove(pw).expect("malformed pk must still prove (gadget outputs false)");
        data.verify(proof.clone()).expect("malformed pk proof must verify");
        assert_eq!(proof.public_inputs[0], F::ZERO, "off-curve public key must output 0");
    }

    // The five Constant* variants that were unrouted dead code until the
    // exec_context routing landed (ModConstantDividend/Divisor,
    // U32And/Or/XorConstant), pinned at both the circuit builder and the VM
    // witness executor against native arithmetic. The constant travels as a
    // regular Constant/ConstantU32 child input (node-ref layout) — the old
    // witness/circuit arms read a register index instead of the value.
    #[test]
    fn dpn_mod_and_u32_bitwise_constant_variants_match_native() {
        use psy_vm::dpn::vm::exec::SimpleDPNExecutor;

        const X: u64 = 0xF0F0_1234;
        const MASK: u64 = 0x0F0F_0F0F;
        const DIVIDEND: u64 = 1_000_003;
        const DIVISOR: u64 = 4242;
        const RUNTIME_DIV: u64 = 37; // runtime divisor read from inputs[1]

        let u32_ref = |i: usize| encode_indexed_op_id(DPNBuiltInDataType::U32Target, i);
        let tgt_ref = |i: usize| encode_indexed_op_id(DPNBuiltInDataType::Target, i);

        let defs = vec![
            // u32 lane: runtime X <op> constant MASK.
            DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::U32Target,
                index: 0,
                op_type: DPNOpType::U32InputTarget,
                inputs: vec![0],
            },
            DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::U32Target,
                index: 1,
                op_type: DPNOpType::ConstantU32,
                inputs: vec![MASK],
            },
            DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::U32Target,
                index: 2,
                op_type: DPNOpType::U32AndConstant,
                inputs: vec![u32_ref(0), u32_ref(1)],
            },
            DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::U32Target,
                index: 3,
                op_type: DPNOpType::U32OrConstant,
                inputs: vec![u32_ref(0), u32_ref(1)],
            },
            DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::U32Target,
                index: 4,
                op_type: DPNOpType::U32XorConstant,
                inputs: vec![u32_ref(0), u32_ref(1)],
            },
            // felt lane: ModConstantDividend = DIVIDEND % d (d runtime),
            // ModConstantDivisor = d % DIVISOR.
            DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::Target,
                index: 0,
                op_type: DPNOpType::InputTarget,
                inputs: vec![1],
            },
            DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::Target,
                index: 1,
                op_type: DPNOpType::Constant,
                inputs: vec![DIVIDEND],
            },
            DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::Target,
                index: 2,
                op_type: DPNOpType::ModConstantDividend,
                inputs: vec![tgt_ref(1), tgt_ref(0)],
            },
            DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::Target,
                index: 3,
                op_type: DPNOpType::Constant,
                inputs: vec![DIVISOR],
            },
            DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::Target,
                index: 4,
                op_type: DPNOpType::ModConstantDivisor,
                inputs: vec![tgt_ref(0), tgt_ref(3)],
            },
        ];

        let expected = [X & MASK, X | MASK, X ^ MASK, DIVIDEND % RUNTIME_DIV, RUNTIME_DIV % DIVISOR];

        // Circuit layer: prove and check the public inputs.
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let input_targets: Vec<Target> = (0..2).map(|_| builder.add_virtual_target()).collect();
        let mut executor = SimpleDPNBuilder::new_with_contract_ctx(
            input_targets.clone(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            dummy_hash(&mut builder),
            dummy_hash(&mut builder),
        );
        for def in &defs {
            executor.process_var_def(&mut builder, def);
        }
        let out2 = executor.resolve_u32(&mut builder, u32_ref(2));
        let out3 = executor.resolve_u32(&mut builder, u32_ref(3));
        let out4 = executor.resolve_u32(&mut builder, u32_ref(4));
        builder.register_public_input(out2.0);
        builder.register_public_input(out3.0);
        builder.register_public_input(out4.0);
        builder.register_public_input(executor.resolve_target(tgt_ref(2)));
        builder.register_public_input(executor.resolve_target(tgt_ref(4)));

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(input_targets[0], F::from_canonical_u64(X)).unwrap();
        pw.set_target(input_targets[1], F::from_canonical_u64(RUNTIME_DIV)).unwrap();
        let proof = data.prove(pw).expect("Constant* variant circuit must prove");
        data.verify(proof.clone()).expect("Constant* variant proof must verify");
        for (got, want) in proof.public_inputs.iter().zip(expected) {
            assert_eq!(*got, F::from_canonical_u64(want), "circuit Constant* variant mismatch");
        }

        // VM witness layer: same var defs, directly executed.
        let mut exec = SimpleDPNExecutor::<F>::new_with_contract_ctx(
            vec![F::from_canonical_u64(X), F::from_canonical_u64(RUNTIME_DIV)],
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            [F::ZERO; 4],
            [F::ZERO; 4],
        );
        for def in &defs {
            exec.process_var_def(def);
        }
        assert_eq!(exec.resolve_u32(u32_ref(2)) as u64, expected[0], "witness U32AndConstant");
        assert_eq!(exec.resolve_u32(u32_ref(3)) as u64, expected[1], "witness U32OrConstant");
        assert_eq!(exec.resolve_u32(u32_ref(4)) as u64, expected[2], "witness U32XorConstant");
        assert_eq!(exec.resolve_target(tgt_ref(2)).to_canonical_u64(), expected[3], "witness ModConstantDividend");
        assert_eq!(exec.resolve_target(tgt_ref(4)).to_canonical_u64(), expected[4], "witness ModConstantDivisor");
    }

    // Dynamic-distance left shifts must clamp distances >= 32 to the
    // zero-result case exactly like the native executors: the old circuit
    // multiplied by low32(2^d mod p), which is not zero for large d. Also
    // pins the truncating shift for d < 32 (0xffffffff << 4 = 0xfffffff0).
    #[test]
    fn dpn_dynamic_shift_left_distances_match_native() {
        use psy_vm::dpn::ops::semantics;
        use psy_vm::dpn::vm::exec::SimpleDPNExecutor;

        const A: u64 = 0xFFFF_FFFF; // every bit set: truncation is observable
        const CONST_VALUE: u64 = 0x1234_5678; // for U32ShiftLeftConstantValue
        const DISTANCES: [u64; 7] = [0, 4, 31, 32, 33, 64, 100];

        let u32_ref = |i: usize| encode_indexed_op_id(DPNBuiltInDataType::U32Target, i);

        let mut defs = vec![DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::U32Target,
            index: 0,
            op_type: DPNOpType::U32InputTarget,
            inputs: vec![0],
        }];
        // Distance constants (indices 1..=7), then A << d (8..=14).
        for (i, &d) in DISTANCES.iter().enumerate() {
            defs.push(DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::U32Target,
                index: 1 + i,
                op_type: DPNOpType::ConstantU32,
                inputs: vec![d],
            });
        }
        for (i, _) in DISTANCES.iter().enumerate() {
            defs.push(DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::U32Target,
                index: 8 + i,
                op_type: DPNOpType::U32ShiftLeft,
                inputs: vec![u32_ref(0), u32_ref(1 + i)],
            });
        }
        // Constant value, dynamic distance (15 = value, 16/17 = results).
        defs.push(DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::U32Target,
            index: 15,
            op_type: DPNOpType::ConstantU32,
            inputs: vec![CONST_VALUE],
        });
        defs.push(DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::U32Target,
            index: 16,
            op_type: DPNOpType::U32ShiftLeftConstantValue,
            inputs: vec![u32_ref(15), u32_ref(2)], // distance 4
        });
        defs.push(DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::U32Target,
            index: 17,
            op_type: DPNOpType::U32ShiftLeftConstantValue,
            inputs: vec![u32_ref(15), u32_ref(4)], // distance 33
        });

        let mut expected: Vec<u64> = DISTANCES
            .iter()
            .map(|&d| semantics::u32_shl(A as u32, d as u32) as u64)
            .collect();
        expected.push(semantics::u32_shl(CONST_VALUE as u32, 4) as u64);
        expected.push(0); // distance 33 folds to zero

        // Circuit layer: prove and check the public inputs.
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let input_targets: Vec<Target> = vec![builder.add_virtual_target()];
        let mut executor = SimpleDPNBuilder::new_with_contract_ctx(
            input_targets.clone(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            dummy_hash(&mut builder),
            dummy_hash(&mut builder),
        );
        for def in &defs {
            executor.process_var_def(&mut builder, def);
        }
        let mut shift_outputs = Vec::with_capacity(9);
        for i in 8..15 {
            shift_outputs.push(executor.resolve_u32(&mut builder, u32_ref(i)).0);
        }
        shift_outputs.push(executor.resolve_u32(&mut builder, u32_ref(16)).0);
        shift_outputs.push(executor.resolve_u32(&mut builder, u32_ref(17)).0);
        for out in shift_outputs {
            builder.register_public_input(out);
        }

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(input_targets[0], F::from_canonical_u64(A)).unwrap();
        let proof = data.prove(pw).expect("dynamic shift-left circuit must prove");
        data.verify(proof.clone()).expect("dynamic shift-left proof must verify");
        for (got, want) in proof.public_inputs.iter().zip(&expected) {
            assert_eq!(*got, F::from_noncanonical_u64(*want), "circuit shift mismatch");
        }

        // VM witness layer: same var defs, directly executed.
        let mut exec = SimpleDPNExecutor::<F>::new_with_contract_ctx(
            vec![F::from_canonical_u64(A)],
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            [F::ZERO; 4],
            [F::ZERO; 4],
        );
        for def in &defs {
            exec.process_var_def(def);
        }
        for (i, want) in expected.iter().take(7).enumerate() {
            let got = exec.resolve_u32(u32_ref(8 + i)) as u64;
            assert_eq!(got, *want, "witness shift mismatch at def {}", 8 + i);
        }
        assert_eq!(exec.resolve_u32(u32_ref(16)) as u64, expected[7], "witness ConstantValue d=4");
        assert_eq!(exec.resolve_u32(u32_ref(17)) as u64, expected[8], "witness ConstantValue d=33");
    }

    // ---------- end-to-end: QExecContext -> injest_sfr -> witness + circuit ----------

    use psy_vm::dpn::{
        ops::{context_trait::DPNContext, exec_context::QExecContext, sym_felt::SymFeltRef},
        vm::compile::PsyCompileResult,
    };

    /// Build a program through the production path (QExecContext ops ->
    /// compile_exec/injest_sfr) and return the compiled definition. The
    /// outputs are felt-lane refs so both layers resolve them identically.
    fn compile_e2e_program(build: impl FnOnce(&mut QExecContext) -> Vec<SymFeltRef>)
        -> psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition {
        let mut ctx = QExecContext::new();
        let outputs = build(&mut ctx);
        PsyCompileResult::compile_exec("e2e".to_string(), 0, &ctx.store, &ctx, &outputs)
    }

    /// Feed the same compiled definition through the VM witness executor
    /// and the proving circuit; both must produce `expected` outputs.
    fn run_e2e_witness_and_circuit(
        defn: &psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition,
        input_values: &[u64],
        expected: &[u64],
    ) {
        // VM witness layer.
        let mut exec = psy_vm::dpn::vm::exec::SimpleDPNExecutor::<F>::new_with_contract_ctx(
            input_values.iter().map(|v| F::from_noncanonical_u64(*v)).collect(),
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            [F::ZERO; 4],
            [F::ZERO; 4],
        );
        for def in &defn.definitions {
            exec.process_var_def(def);
        }
        for (i, (&out, want)) in defn.circuit_outputs.iter().zip(expected).enumerate() {
            let got = exec.resolve_target(out).to_canonical_u64();
            assert_eq!(got, *want, "witness output #{i} mismatch");
        }

        // Circuit layer: prove, verify, compare the public inputs.
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let input_targets: Vec<Target> =
            (0..defn.circuit_inputs.len()).map(|_| builder.add_virtual_target()).collect();
        let mut circuit = SimpleDPNBuilder::new_with_contract_ctx(
            input_targets.clone(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            dummy_hash(&mut builder),
            dummy_hash(&mut builder),
        );
        for def in &defn.definitions {
            circuit.process_var_def(&mut builder, def);
        }
        for out in &defn.circuit_outputs {
            builder.register_public_input(circuit.resolve_target(*out));
        }
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        for (t, v) in input_targets.iter().zip(input_values) {
            pw.set_target(*t, F::from_noncanonical_u64(*v)).unwrap();
        }
        let proof = data.prove(pw).expect("e2e circuit must prove");
        data.verify(proof.clone()).expect("e2e proof must verify");
        for (i, (got, want)) in proof.public_inputs.iter().zip(expected).enumerate() {
            assert_eq!(*got, F::from_noncanonical_u64(*want), "circuit output #{i} mismatch");
        }
    }

    /// Both layers must reject the program for the given inputs: the
    /// witness panics and the circuit has no satisfying assignment.
    fn expect_e2e_both_reject(
        defn: &psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition,
        input_values: &[u64],
    ) {
        let witness = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut exec = psy_vm::dpn::vm::exec::SimpleDPNExecutor::<F>::new_with_contract_ctx(
                input_values.iter().map(|v| F::from_noncanonical_u64(*v)).collect(),
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                [F::ZERO; 4],
                [F::ZERO; 4],
            );
            for def in &defn.definitions {
                exec.process_var_def(def);
            }
        }));
        assert!(witness.is_err(), "witness must reject the invalid program");

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let input_targets: Vec<Target> =
            (0..defn.circuit_inputs.len()).map(|_| builder.add_virtual_target()).collect();
        let mut circuit = SimpleDPNBuilder::new_with_contract_ctx(
            input_targets.clone(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            dummy_hash(&mut builder),
            dummy_hash(&mut builder),
        );
        for def in &defn.definitions {
            circuit.process_var_def(&mut builder, def);
        }
        for out in &defn.circuit_outputs {
            builder.register_public_input(circuit.resolve_target(*out));
        }
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        for (t, v) in input_targets.iter().zip(input_values) {
            pw.set_target(*t, F::from_noncanonical_u64(*v)).unwrap();
        }
        assert!(data.prove(pw).is_err(), "circuit must be unsatisfiable for the invalid program");
    }

    #[test]
    fn dpn_e2e_sum_bits_roundtrip_weighted_matches_native() {
        let defn = compile_e2e_program(|ctx| {
            let x = ctx.add_u32_input();
            let x = ctx.op_cast_felt(x);
            let bits = ctx.split_bits(x, 32);
            vec![ctx.sum_bits(&bits)]
        });
        // 0xffff_ffff reconstructs exactly; an unweighted (popcount) sum
        // would yield 32.
        run_e2e_witness_and_circuit(&defn, &[0xffff_ffff], &[0xffff_ffff]);
        // A sparse pattern keeps the weighted/unweighted distinction sharp
        // (weighted 0x8000_0001 vs popcount 2).
        run_e2e_witness_and_circuit(&defn, &[0x8000_0001], &[0x8000_0001]);
    }

    #[test]
    fn dpn_e2e_dynamic_shift_left_clamps_matches_native() {
        use psy_vm::dpn::ops::semantics;
        let defn = compile_e2e_program(|ctx| {
            let a = ctx.add_u32_input();
            let d = ctx.add_u32_input(); // runtime distance
            let mut outs = vec![ctx.op_u32_shl(a, d)]; // plain U32ShiftLeft
            for dist in [0u32, 4, 31, 32, 33, 64] {
                // Constant distances route to the ConstantBitDistance variant.
                let cd = ctx.op_const_u32(dist);
                outs.push(ctx.op_u32_shl(a, cd));
            }
            outs.into_iter().map(|o| ctx.op_cast_felt(o)).collect()
        });
        let (a, d) = (0xffff_ffffu64, 33u64);
        let mut expected = vec![semantics::u32_shl(a as u32, d as u32) as u64];
        for dist in [0u32, 4, 31, 32, 33, 64] {
            expected.push(semantics::u32_shl(a as u32, dist) as u64);
        }
        run_e2e_witness_and_circuit(&defn, &[a, d], &expected);
    }

    #[test]
    fn dpn_e2e_u32_arith_edges_match_native() {
        let defn = compile_e2e_program(|ctx| {
            let a = ctx.add_u32_input(); // 0xffff_fffe
            let b = ctx.add_u32_input(); // 10
            let out_sub = ctx.op_u32_sub(a, a); // equality allowed: 0
            let one = ctx.op_const_u32(1);
            let out_add = ctx.op_u32_add(a, one); // legal max
            let three = ctx.op_const_u32(3);
            let out_exp = ctx.op_u32_exp(three, b); // 3^10
            let max_felt = ctx.op_const(0xffff_ffff);
            let max_u32 = ctx.op_cast_u32(max_felt);
            let out_cast = ctx.op_cast_felt(max_u32);
            let one_felt = ctx.op_const(1);
            let one_bool = ctx.op_cast_bool(one_felt);
            let out_bool = ctx.op_cast_felt(one_bool);
            vec![
                ctx.op_cast_felt(out_sub),
                ctx.op_cast_felt(out_add),
                ctx.op_cast_felt(out_exp),
                out_cast,
                out_bool,
            ]
        });
        run_e2e_witness_and_circuit(&defn, &[0xffff_fffe, 10], &[0, 0xffff_ffff, 59_049, 0xffff_ffff, 1]);
    }

    #[test]
    fn dpn_e2e_u32_overflows_rejected_by_both_layers() {
        // add overflow: 0xffffffff + 1.
        let defn = compile_e2e_program(|ctx| {
            let a = ctx.add_u32_input();
            let one = ctx.op_const_u32(1);
            let s = ctx.op_u32_add(a, one);
            vec![ctx.op_cast_felt(s)]
        });
        expect_e2e_both_reject(&defn, &[0xffff_ffff]);

        // mul overflow: 0x10000 * 0x10000.
        let defn = compile_e2e_program(|ctx| {
            let a = ctx.add_u32_input();
            let big = ctx.op_const_u32(0x1_0000);
            let s = ctx.op_u32_mul(a, big);
            vec![ctx.op_cast_felt(s)]
        });
        expect_e2e_both_reject(&defn, &[0x1_0000]);

        // sub underflow: 5 - 6.
        let defn = compile_e2e_program(|ctx| {
            let a = ctx.add_u32_input();
            let six = ctx.op_const_u32(6);
            let s = ctx.op_u32_sub(a, six);
            vec![ctx.op_cast_felt(s)]
        });
        expect_e2e_both_reject(&defn, &[5]);

        // cast_u32 of a felt above the u32 lane.
        let defn = compile_e2e_program(|ctx| {
            let x = ctx.add_input();
            let u = ctx.op_cast_u32(x);
            vec![ctx.op_cast_felt(u)]
        });
        expect_e2e_both_reject(&defn, &[0x1_0000_0000]);

        // cast_bool of a non-boolean felt.
        let defn = compile_e2e_program(|ctx| {
            let x = ctx.add_input();
            let b = ctx.op_cast_bool(x);
            vec![ctx.op_cast_felt(b)]
        });
        expect_e2e_both_reject(&defn, &[2]);

        // keccak256 word above the u32 lane.
        let defn = compile_e2e_program(|ctx| {
            let x = ctx.add_input();
            let digest = ctx.keccak256(&[x]);
            digest.to_vec()
        });
        expect_e2e_both_reject(&defn, &[0x1_0000_0000]);
    }

    #[test]
    fn dpn_e2e_felt_comparisons_top_bit_operands_match_native() {
        // The 64-bit two-limb comparator covers the full canonical field
        // range. Operands with the top bit set (and near p) must compare
        // identically to native u64 ordering on both layers.
        let pairs: [(u64, u64); 3] = [
            (1 << 63, (1 << 63) - 1),
            (0xffff_ffff_0000_0000, 0xffff_ffff_0000_0000), // equal operands
            (0xffff_fffe_ffff_ffff, 0), // p - 1 vs 0
        ];
        let defn = compile_e2e_program(|ctx| {
            let mut outs = Vec::new();
            for (l, r) in pairs {
                let (l, r) = (ctx.op_const(l), ctx.op_const(r));
                let v = ctx.op_lt(l, r);
                outs.push(ctx.op_cast_felt(v));
                let v = ctx.op_lte(l, r);
                outs.push(ctx.op_cast_felt(v));
                let v = ctx.op_gt(l, r);
                outs.push(ctx.op_cast_felt(v));
                let v = ctx.op_gte(l, r);
                outs.push(ctx.op_cast_felt(v));
            }
            outs
        });
        let mut expected = Vec::new();
        for (l, r) in pairs {
            expected.push((l < r) as u64);
            expected.push((l <= r) as u64);
            expected.push((l > r) as u64);
            expected.push((l >= r) as u64);
        }
        run_e2e_witness_and_circuit(&defn, &[], &expected);
    }

    #[test]
    fn dpn_e2e_keccak256_u32_range_inputs_match_native() {
        use psy_vm::dpn::ops::semantics;
        let defn = compile_e2e_program(|ctx| {
            let w0 = ctx.add_u32_input();
            let w0 = ctx.op_cast_felt(w0);
            let w1 = ctx.add_u32_input();
            let w1 = ctx.op_cast_felt(w1);
            let digest = ctx.keccak256(&[w0, w1]);
            digest.to_vec()
        });
        let words = [0x0123_4567u64, 0x89ab_cdef];
        let expected: Vec<u64> =
            semantics::keccak_u32_words_be(&words).unwrap().into_iter().map(|w| w as u64).collect();
        run_e2e_witness_and_circuit(&defn, &words, &expected);
    }

    // DivRem4 was declared on the Target lane while both the witness and the
    // circuit write a two-element target array - the pool counters desynced.
    // The lane is now TargetArray; this pins [quotient, remainder] at both
    // layers through a hand-built definition list.
    #[test]
    fn dpn_div_rem4_matches_native() {
        use psy_vm::dpn::vm::exec::SimpleDPNExecutor;

        const X: u64 = 0x1234_5678_9abc_def7;

        let tgt_ref = |i: usize| encode_indexed_op_id(DPNBuiltInDataType::Target, i);
        let arr_ref = |i: usize| encode_indexed_op_id(DPNBuiltInDataType::TargetArray, i);

        let defs = vec![
            DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::Target,
                index: 0,
                op_type: DPNOpType::InputTarget,
                inputs: vec![0],
            },
            DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::Target,
                index: 1,
                op_type: DPNOpType::Constant,
                inputs: vec![0],
            },
            DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::TargetArray,
                index: 0,
                op_type: DPNOpType::DivRem4,
                inputs: vec![tgt_ref(0)],
            },
            DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::Target,
                index: 2,
                op_type: DPNOpType::TargetAt,
                inputs: vec![arr_ref(0), tgt_ref(1)],
            },
            DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::Target,
                index: 3,
                op_type: DPNOpType::Constant,
                inputs: vec![1],
            },
            DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::Target,
                index: 4,
                op_type: DPNOpType::TargetAt,
                inputs: vec![arr_ref(0), tgt_ref(3)],
            },
        ];
        let expected = [X >> 2, X & 3];

        // Circuit layer.
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let input_targets: Vec<Target> = vec![builder.add_virtual_target()];
        let mut executor = SimpleDPNBuilder::new_with_contract_ctx(
            input_targets.clone(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            builder.zero(),
            dummy_hash(&mut builder),
            dummy_hash(&mut builder),
        );
        for def in &defs {
            executor.process_var_def(&mut builder, def);
        }
        let out_q = executor.resolve_target(tgt_ref(2));
        let out_r = executor.resolve_target(tgt_ref(4));
        builder.register_public_input(out_q);
        builder.register_public_input(out_r);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(input_targets[0], F::from_noncanonical_u64(X)).unwrap();
        let proof = data.prove(pw).expect("DivRem4 circuit must prove");
        data.verify(proof.clone()).expect("DivRem4 proof must verify");
        for (got, want) in proof.public_inputs.iter().zip(expected) {
            assert_eq!(*got, F::from_noncanonical_u64(want), "circuit DivRem4 mismatch");
        }

        // VM witness layer.
        let mut exec = SimpleDPNExecutor::<F>::new_with_contract_ctx(
            vec![F::from_noncanonical_u64(X)],
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            [F::ZERO; 4],
            [F::ZERO; 4],
        );
        for def in &defs {
            exec.process_var_def(def);
        }
        assert_eq!(exec.resolve_target(tgt_ref(2)).to_canonical_u64(), expected[0], "witness quotient");
        assert_eq!(exec.resolve_target(tgt_ref(4)).to_canonical_u64(), expected[1], "witness remainder");
    }
}
