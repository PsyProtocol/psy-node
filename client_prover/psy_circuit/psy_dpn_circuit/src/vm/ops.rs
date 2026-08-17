use std::{collections::HashMap, marker::PhantomData};

use plonky2::{
    field::{extension::Extendable, secp256k1_base::Secp256K1Base, secp256k1_scalar::Secp256K1Scalar},
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use psy_client_data::{config::store_config::PsyHasher, dpn::sd_key::SDKEY_MAX_CALLDATA_WORDS};
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

const COMPARISON_BITS: usize = 63;

#[derive(Clone, Debug)]
pub struct DPNTransactionEntryTargets {
    pub caller_contract_id: Target,
    pub contract_id: Target,
    pub method_id: Target,
    pub inputs_length: Target,
    pub inputs_hash: HashOutTarget,
    pub inputs: Vec<Target>,
}

#[derive(Clone, Debug)]
pub struct DPNTransactionContextTargets {
    pub tx_count: Target,
    pub tx_stack_hash: HashOutTarget,
    pub entries: Vec<DPNTransactionEntryTargets>,
}

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
    pub transaction_context: Option<DPNTransactionContextTargets>,
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
            transaction_context: None,
        }
    }
    pub fn set_transaction_context(&mut self, context: DPNTransactionContextTargets) {
        self.transaction_context = Some(context);
    }

    fn transaction_index_target(&self, op: &DPNIndexedVarDef) -> Target {
        assert_eq!(op.inputs.len(), 1, "transaction introspection opcode requires one index input");
        self.resolve_target(op.inputs[0])
    }

    fn select_transaction_target(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        index: Target,
        field: fn(&DPNTransactionEntryTargets) -> Target,
    ) -> Target {
        let context = self
            .transaction_context
            .as_ref()
            .expect("transaction introspection context is not attached");
        let in_range = builder.is_less_than(COMPARISON_BITS, index, context.tx_count);
        builder.assert_one(in_range.target);
        let mut selected = builder.zero();
        let mut valid = builder._false();
        for (entry_index, entry) in context.entries.iter().enumerate() {
            let matches = builder.is_equal_to_u64(index, entry_index as u64);
            selected = builder.select(matches, field(entry), selected);
            valid = builder.or(valid, matches);
        }
        builder.assert_one(valid.target);
        selected
    }

    fn select_transaction_hash(&self, builder: &mut CircuitBuilder<F, D>, index: Target) -> HashOutTarget {
        let context = self
            .transaction_context
            .as_ref()
            .expect("transaction introspection context is not attached");
        let in_range = builder.is_less_than(COMPARISON_BITS, index, context.tx_count);
        builder.assert_one(in_range.target);
        let mut selected = HashOutTarget {
            elements: [builder.zero(); 4],
        };
        let mut valid = builder._false();
        for (entry_index, entry) in context.entries.iter().enumerate() {
            let matches = builder.is_equal_to_u64(index, entry_index as u64);
            for limb in 0..4 {
                selected.elements[limb] = builder.select(matches, entry.inputs_hash.elements[limb], selected.elements[limb]);
            }
            valid = builder.or(valid, matches);
        }
        builder.assert_one(valid.target);
        selected
    }

    fn select_transaction_length(&self, builder: &mut CircuitBuilder<F, D>, index: Target) -> Target {
        self.select_transaction_target(builder, index, |entry| entry.inputs_length)
    }

    fn select_transaction_input_word(&self, builder: &mut CircuitBuilder<F, D>, tx_index: Target, word_index: Target) -> Target {
        let context = self
            .transaction_context
            .as_ref()
            .expect("transaction introspection context is not attached");
        let in_range = builder.is_less_than(COMPARISON_BITS, tx_index, context.tx_count);
        builder.assert_one(in_range.target);
        let max_word_index = builder.constant(F::from_canonical_u64(SDKEY_MAX_CALLDATA_WORDS as u64));
        let word_in_range = builder.is_less_than(COMPARISON_BITS, word_index, max_word_index);
        builder.assert_one(word_in_range.target);
        // The fixed transaction context has 128 witness targets per slot, but
        // only the prefix below inputs_length is authenticated by inputs_hash.
        // Reject reads from the padded tail instead of exposing unconstrained
        // witness values.
        let inputs_length = self.select_transaction_length(builder, tx_index);
        let word_is_in_calldata = builder.is_less_than(COMPARISON_BITS, word_index, inputs_length);
        builder.assert_one(word_is_in_calldata.target);

        let mut selected = builder.zero();
        let mut valid_tx = builder._false();
        for (entry_index, entry) in context.entries.iter().enumerate() {
            let tx_matches = builder.is_equal_to_u64(tx_index, entry_index as u64);
            valid_tx = builder.or(valid_tx, tx_matches);
            let mut selected_word = builder.zero();
            for (word, value) in entry.inputs.iter().enumerate() {
                let word_matches = builder.is_equal_to_u64(word_index, word as u64);
                selected_word = builder.select(word_matches, *value, selected_word);
            }
            selected = builder.select(tx_matches, selected_word, selected);
        }
        builder.assert_one(valid_tx.target);
        selected
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
    pub fn resolve_u32(&self, id: u64) -> U32Target {
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
                // TODO/SECURITY: range check target
                U32Target(self.targets[index].expect("Unassigned target index"))
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
    pub fn resolve_target_array_ref(&self, id: u64, index_id: u64) -> Target {
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
                self.resolve_u32(id).0
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
                let r = self.resolve_target_array_ref(op.inputs[0], op.inputs[1]);
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
            DPNOpType::ExpConstantPower => {
                let left = self.resolve_target(op.inputs[0]);
                let right_value = builder
                    .target_as_constant(self.resolve_u32(op.inputs[1]).0)
                    .expect("ExpConstantPower right must be constant")
                    .to_canonical_u64();

                self.set_target_at(op.index as usize, builder.exp_u64(left, right_value as u64), "ExpConstantPower")
            }
            DPNOpType::ExpConstantBase => {
                let left_value = builder
                    .target_as_constant(self.resolve_u32(op.inputs[1]).0)
                    .expect("ExpConstantBase left must be constant");
                let right = builder.split_le(self.resolve_target(op.inputs[1]), 64);
                self.set_target_at(op.index as usize, builder.exp_from_bits_const_base(left_value, right), "ExpConstantBase")
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
            DPNOpType::U32And => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
                self.set_u32_at(op.index as usize, builder.and_u32(left, right), "U32And");
            }
            DPNOpType::U32AndConstant => {
                let left = self.resolve_u32(op.inputs[0]);
                let (_op_type, right) = decode_indexed_op_id(op.inputs[1]);
                let right = builder.constant_u32(right as u32);
                self.set_u32_at(op.index as usize, builder.and_u32(left, right), "U32AndConstant");
            }
            DPNOpType::U32Or => {
                let neg_left = builder.not_u32(self.resolve_u32(op.inputs[0]));
                let neg_right = builder.not_u32(self.resolve_u32(op.inputs[1]));
                let neg_left_or_right = builder.and_u32(neg_left, neg_right);
                self.set_u32_at(op.index as usize, builder.not_u32(neg_left_or_right), "U32Or");
            }
            DPNOpType::U32OrConstant => {
                let neg_left = builder.not_u32(self.resolve_u32(op.inputs[0]));
                let (_op_type, right) = decode_indexed_op_id(op.inputs[1]);
                let neg_right = builder.constant_u32(0xffffffff - (right as u32));
                let neg_left_or_right = builder.and_u32(neg_left, neg_right);
                self.set_u32_at(op.index as usize, builder.not_u32(neg_left_or_right), "U32OrConstant");
            }
            DPNOpType::U32Xor => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
                self.set_u32_at(op.index as usize, builder.xor_u32(left, right), "U32Xor");
            }
            DPNOpType::U32XorConstant => {
                let left = self.resolve_u32(op.inputs[0]);
                let (_op_type, right) = decode_indexed_op_id(op.inputs[1]);
                let right = builder.constant_u32(right as u32);
                self.set_u32_at(op.index as usize, builder.xor_u32(left, right), "U32XorConstant");
            }
            DPNOpType::U32ShiftLeft => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
                let two = builder.two();
                let power_of_two = builder.exp(two, right.0, 32);
                let (power_of_two_low, _power_of_two_heigh) =
                    psy_common_circuit::builder::core::CircuitBuilderHelpersCore::split_low_high_32bits(builder, power_of_two);
                self.set_u32_at(op.index as usize, builder.mul_u32(left, U32Target(power_of_two_low)).0, "U32ShiftLeft");
            }
            DPNOpType::U32ShiftLeftConstantBitDistance => {
                let left = self.resolve_u32(op.inputs[0]);
                let right_value = builder
                    .target_as_constant(self.resolve_u32(op.inputs[1]).0)
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
                let left = self.resolve_u32(op.inputs[0]);
                let _left_value = builder
                    .target_as_constant(self.resolve_u32(op.inputs[0]).0)
                    .expect("U32ShiftLeftConstantValue left must be constant")
                    .to_canonical_u64();
                let right = self.resolve_u32(op.inputs[1]);
                let two = builder.two();
                let power_of_two = builder.exp(two, right.0, 32);
                let (power_of_two_low, _power_of_two_heigh) =
                    psy_common_circuit::builder::core::CircuitBuilderHelpersCore::split_low_high_32bits(builder, power_of_two);
                self.set_u32_at(
                    op.index as usize,
                    builder.mul_u32(left, U32Target(power_of_two_low)).0,
                    "U32ShiftLeftConstantValue",
                );
            }
            DPNOpType::U32ShiftRight => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);

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
                let left = self.resolve_u32(op.inputs[0]);
                let right_value = builder
                    .target_as_constant(self.resolve_u32(op.inputs[1]).0)
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
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
                let left_value = builder
                    .target_as_constant(self.resolve_u32(op.inputs[0]).0)
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
            DPNOpType::GetTransactionCount => {
                let context = self
                    .transaction_context
                    .as_ref()
                    .expect("transaction introspection context is not attached");
                self.set_target_at(op.index as usize, context.tx_count, "GetTransactionCount");
            }
            DPNOpType::GetTransactionStackHash => {
                let context = self
                    .transaction_context
                    .as_ref()
                    .expect("transaction introspection context is not attached");
                self.set_hash_at(op.index as usize, context.tx_stack_hash, "GetTransactionStackHash");
            }
            DPNOpType::GetTransactionContractId => {
                let index = self.transaction_index_target(op);
                let value = self.select_transaction_target(builder, index, |entry| entry.contract_id);
                self.set_target_at(op.index as usize, value, "GetTransactionContractId");
            }
            DPNOpType::GetTransactionCallerContractId => {
                let index = self.transaction_index_target(op);
                let value = self.select_transaction_target(builder, index, |entry| entry.caller_contract_id);
                self.set_target_at(op.index as usize, value, "GetTransactionCallerContractId");
            }
            DPNOpType::GetTransactionMethodId => {
                let index = self.transaction_index_target(op);
                let value = self.select_transaction_target(builder, index, |entry| entry.method_id);
                self.set_target_at(op.index as usize, value, "GetTransactionMethodId");
            }
            DPNOpType::GetTransactionInputsHash => {
                let index = self.transaction_index_target(op);
                let value = self.select_transaction_hash(builder, index);
                self.set_hash_at(op.index as usize, value, "GetTransactionInputsHash");
            }
            DPNOpType::GetTransactionInputLength => {
                let index = self.transaction_index_target(op);
                let value = self.select_transaction_length(builder, index);
                self.set_target_at(op.index as usize, value, "GetTransactionInputLength");
            }
            DPNOpType::GetTransactionInputWord => {
                assert_eq!(op.inputs.len(), 2, "GetTransactionInputWord requires transaction and word indices");
                let tx_index = self.resolve_target(op.inputs[0]);
                let word_index = self.resolve_target(op.inputs[1]);
                let value = self.select_transaction_input_word(builder, tx_index, word_index);
                self.set_target_at(op.index as usize, value, "GetTransactionInputWord");
            }

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
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
                let (low, high) = builder.add_u32(left, right);
                builder.assert_zero(high.0);
                self.set_u32_at(op.index as usize, low, "U32Add");
            }
            DPNOpType::U32Sub => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
                let zero = builder.zero_u32();
                let (low, high) = builder.sub_u32(left, right, zero);
                builder.assert_zero(high.0);
                self.set_u32_at(op.index as usize, low, "U32Sub");
            }
            DPNOpType::U32Mul => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
                let (low, high) = builder.mul_u32(left, right);
                builder.assert_zero(high.0);
                self.set_u32_at(op.index as usize, low, "U32Mul");
            }
            DPNOpType::U32Div => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);

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
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);

                let left_biguint = BigUintTarget { limbs: vec![left] };
                let right_biguint = BigUintTarget { limbs: vec![right] };
                let (_div_biguint, rem_biguint) = builder.div_rem_biguint(&left_biguint, &right_biguint);

                assert!(rem_biguint.limbs.len() == 1, "U32 Mod should only return one limb");

                let div = rem_biguint.limbs[0];
                self.set_u32_at(op.index as usize, div, "U32Mod");
            }
            DPNOpType::U32Exp => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
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

                let pk_x_u32_target = op.inputs[0..8].iter().map(|id| self.resolve_u32(*id)).collect::<Vec<_>>();
                let pk_x_target = NonNativeTarget::<Secp256K1Base> {
                    value: BigUintTarget {
                        limbs: pk_x_u32_target.to_vec(),
                    },
                    _phantom: PhantomData,
                };
                let pk_y_u32_target = op.inputs[8..16].iter().map(|id| self.resolve_u32(*id)).collect::<Vec<_>>();
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
                let r_u32_target = op.inputs[16..24].iter().map(|id| self.resolve_u32(*id)).collect::<Vec<_>>();
                let r = NonNativeTarget::<Secp256K1Scalar> {
                    value: BigUintTarget {
                        limbs: r_u32_target.to_vec(),
                    },
                    _phantom: PhantomData,
                };
                let s_u32_target = op.inputs[24..32].iter().map(|id| self.resolve_u32(*id)).collect::<Vec<_>>();
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
        field::{goldilocks_field::GoldilocksField, types::Field},
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
}
