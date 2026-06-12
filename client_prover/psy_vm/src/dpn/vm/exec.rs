use plonky2::{
    hash::{hash_types::RichField, poseidon::PoseidonHash},
    plonk::config::Hasher,
};
use psy_config::network_constants::DEFAULT_CALLER_CONTRACT_ID_U64;
use tiny_keccak::{Hasher as _, Keccak};

use crate::dpn::ops::op_types::{decode_indexed_op_id, DPNBuiltInDataType, DPNIndexedVarDef, DPNOpType};

pub struct SimpleDPNExecutor<F: RichField> {
    pub targets: Vec<F>,
    pub target_arrays: Vec<Vec<F>>,
    pub hashes: Vec<[F; 4]>,
    pub hash160s: Vec<[u32; 5]>,
    pub bools: Vec<bool>,
    pub bool_arrays: Vec<Vec<bool>>,
    pub u32s: Vec<u32>,
    pub u32_arrays: Vec<Vec<u32>>,
    pub user_id: F,
    pub contract_id: F,
    pub caller_contract_id: F,
    pub checkpoint_id: F,
    pub user_public_key: [F; 4],
    pub session_proof_tree_root: [F; 4],
    pub nonce: F,
    pub inputs: Vec<F>,
}

impl<F: RichField> SimpleDPNExecutor<F> {
    fn should_trace_claim_deposit_hashes(&self) -> bool {
        std::env::var_os("PSY_TRACE_CLAIM_DEPOSIT_HASHES").is_some()
    }

    fn fmt_hash_elements(elements: &[F; 4]) -> String {
        format!(
            "{:016x}{:016x}{:016x}{:016x}",
            elements[3].to_canonical_u64(),
            elements[2].to_canonical_u64(),
            elements[1].to_canonical_u64(),
            elements[0].to_canonical_u64(),
        )
    }

    fn set_target_at(&mut self, index: usize, value: F, source: &str) {
        if index == self.targets.len() {
            self.targets.push(value);
            return;
        }
        if index > self.targets.len() {
            panic!("Sparse target assignment at index {} from {} (len={})", index, source, self.targets.len());
        }
        if self.targets[index] != value {
            panic!(
                "Conflicting target assignment at index {} from {}: existing={:?} new={:?}",
                index, source, self.targets[index], value
            );
        }
    }

    fn set_target_array_at(&mut self, index: usize, value: Vec<F>, source: &str) {
        if index == self.target_arrays.len() {
            self.target_arrays.push(value);
            return;
        }
        if index > self.target_arrays.len() {
            panic!(
                "Sparse target array assignment at index {} from {} (len={})",
                index,
                source,
                self.target_arrays.len()
            );
        }
        if self.target_arrays[index] != value {
            panic!(
                "Conflicting target array assignment at index {} from {}: existing={:?} new={:?}",
                index, source, self.target_arrays[index], value
            );
        }
    }

    fn set_hash_at(&mut self, index: usize, value: [F; 4], source: &str) {
        if index == self.hashes.len() {
            self.hashes.push(value);
            return;
        }
        if index > self.hashes.len() {
            panic!("Sparse hash assignment at index {} from {} (len={})", index, source, self.hashes.len());
        }
        if self.hashes[index] != value {
            panic!(
                "Conflicting hash assignment at index {} from {}: existing={:?} new={:?}",
                index, source, self.hashes[index], value
            );
        }
    }

    fn set_hash160_at(&mut self, index: usize, value: [u32; 5], source: &str) {
        if index == self.hash160s.len() {
            self.hash160s.push(value);
            return;
        }
        if index > self.hash160s.len() {
            panic!(
                "Sparse hash160 assignment at index {} from {} (len={})",
                index,
                source,
                self.hash160s.len()
            );
        }
        if self.hash160s[index] != value {
            panic!(
                "Conflicting hash160 assignment at index {} from {}: existing={:?} new={:?}",
                index, source, self.hash160s[index], value
            );
        }
    }

    fn set_bool_at(&mut self, index: usize, value: bool, source: &str) {
        if index == self.bools.len() {
            self.bools.push(value);
            return;
        }
        if index > self.bools.len() {
            panic!("Sparse bool assignment at index {} from {} (len={})", index, source, self.bools.len());
        }
        if self.bools[index] != value {
            panic!(
                "Conflicting bool assignment at index {} from {}: existing={:?} new={:?}",
                index, source, self.bools[index], value
            );
        }
    }

    fn set_bool_array_at(&mut self, index: usize, value: Vec<bool>, source: &str) {
        if index == self.bool_arrays.len() {
            self.bool_arrays.push(value);
            return;
        }
        if index > self.bool_arrays.len() {
            panic!(
                "Sparse bool array assignment at index {} from {} (len={})",
                index,
                source,
                self.bool_arrays.len()
            );
        }
        if self.bool_arrays[index] != value {
            panic!(
                "Conflicting bool array assignment at index {} from {}: existing={:?} new={:?}",
                index, source, self.bool_arrays[index], value
            );
        }
    }

    fn set_u32_at(&mut self, index: usize, value: u32, source: &str) {
        if index == self.u32s.len() {
            self.u32s.push(value);
            return;
        }
        if index > self.u32s.len() {
            panic!("Sparse u32 assignment at index {} from {} (len={})", index, source, self.u32s.len());
        }
        if self.u32s[index] != value {
            panic!(
                "Conflicting u32 assignment at index {} from {}: existing={:?} new={:?}",
                index, source, self.u32s[index], value
            );
        }
    }

    fn set_u32_array_at(&mut self, index: usize, value: Vec<u32>, source: &str) {
        if index == self.u32_arrays.len() {
            self.u32_arrays.push(value);
            return;
        }
        if index > self.u32_arrays.len() {
            panic!(
                "Sparse u32 array assignment at index {} from {} (len={})",
                index,
                source,
                self.u32_arrays.len()
            );
        }
        if self.u32_arrays[index] != value {
            panic!(
                "Conflicting u32 array assignment at index {} from {}: existing={:?} new={:?}",
                index, source, self.u32_arrays[index], value
            );
        }
    }
    fn keccak256_bytes_to_u32x8(bytes: &[u8]) -> [u32; 8] {
        let mut digest = [0u8; 32];
        let mut keccak = Keccak::v256();
        keccak.update(&bytes);
        keccak.finalize(&mut digest);

        let mut limbs = [0u32; 8];
        for (i, chunk) in digest.chunks_exact(4).enumerate().take(8) {
            let mut limb = [0u8; 4];
            limb.copy_from_slice(chunk);
            limbs[i] = u32::from_be_bytes(limb);
        }
        limbs
    }

    pub fn new() -> Self {
        SimpleDPNExecutor {
            targets: Vec::new(),
            target_arrays: Vec::new(),
            hashes: Vec::new(),
            hash160s: Vec::new(),
            bools: Vec::new(),
            bool_arrays: Vec::new(),
            u32s: Vec::new(),
            u32_arrays: Vec::new(),
            user_id: F::ZERO,
            contract_id: F::ZERO,
            caller_contract_id: F::from_canonical_u64(DEFAULT_CALLER_CONTRACT_ID_U64),
            checkpoint_id: F::ZERO,
            user_public_key: [F::ZERO; 4],
            session_proof_tree_root: [F::ZERO; 4],
            nonce: F::ZERO,
            inputs: Vec::new(),
        }
    }
    pub fn new_with_contract_ctx(
        inputs: Vec<F>,
        user_id: F,
        contract_id: F,
        caller_contract_id: F,
        checkpoint_id: F,
        nonce: F,
        user_public_key: [F; 4],
        session_proof_tree_root: [F; 4],
    ) -> Self {
        SimpleDPNExecutor {
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
        }
    }
    pub fn push_external_target(&mut self, index: usize, target: F) {
        self.set_target_at(index, target, "external_target");
    }
    pub fn push_external_target_array(&mut self, index: usize, target: Vec<F>) {
        self.set_target_array_at(index, target, "external_target_array");
    }
    pub fn push_external_hash(&mut self, index: usize, target: [F; 4]) {
        self.set_hash_at(index, target, "external_hash");
    }
    pub fn resolve_bool(&self, id: u64) -> bool {
        let (t, index) = decode_indexed_op_id(id);
        match t {
            DPNBuiltInDataType::Bool => {
                assert!(index < self.bools.len(), "Invalid bool index");
                self.bools[index]
            }
            DPNBuiltInDataType::Target => {
                assert!(index < self.targets.len(), "Invalid target index");

                let uv = self.targets[index].to_canonical_u64();
                assert!(uv == 1 || uv == 0, "Invalid bool value");
                uv == 1
            }

            DPNBuiltInDataType::U32Target => {
                assert!(index < self.u32s.len(), "Invalid u32 index");

                let uv = self.u32s[index];
                assert!(uv == 1 || uv == 0, "Invalid bool value");
                uv == 1
            }
            _ => panic!("Invalid data type for bool"),
        }
    }
    pub fn resolve_hash(&self, id: u64) -> [F; 4] {
        let (t, index) = decode_indexed_op_id(id);
        match t {
            DPNBuiltInDataType::HashOut => {
                assert!(index < self.hashes.len(), "Invalid hash index");
                self.hashes[index]
            }
            _ => panic!("Invalid data type for hash"),
        }
    }
    pub fn resolve_hash160(&self, id: u64) -> [u32; 5] {
        let (t, index) = decode_indexed_op_id(id);
        match t {
            DPNBuiltInDataType::HashOut160 => {
                assert!(index < self.hashes.len(), "Invalid hash160 index");
                self.hash160s[index]
            }
            _ => panic!("Invalid data type for hash160"),
        }
    }
    pub fn resolve_targets(&self, id: &[u64]) -> Vec<F> {
        id.iter().map(|id| self.resolve_target(*id)).collect()
    }
    pub fn resolve_target(&self, id: u64) -> F {
        let (t, index) = decode_indexed_op_id(id);
        match t {
            DPNBuiltInDataType::Bool => {
                assert!(index < self.bools.len(), "Invalid bool index");
                if self.bools[index] {
                    F::ONE
                } else {
                    F::ZERO
                }
            }
            DPNBuiltInDataType::Target => {
                assert!(index < self.targets.len(), "Invalid target index");
                self.targets[index]
            }

            DPNBuiltInDataType::U32Target => {
                assert!(index < self.u32s.len(), "Invalid u32 index");

                F::from_canonical_u32(self.u32s[index])
            }
            _ => panic!("Invalid data type for target"),
        }
    }
    pub fn resolve_u32(&self, id: u64) -> u32 {
        let (t, index) = decode_indexed_op_id(id);
        match t {
            DPNBuiltInDataType::U32Target => {
                assert!(index < self.u32s.len(), "Invalid u32 index");

                self.u32s[index]
            }
            DPNBuiltInDataType::Bool => {
                assert!(index < self.bools.len(), "Invalid bool index");
                if self.bools[index] {
                    1
                } else {
                    0
                }
            }
            DPNBuiltInDataType::Target => {
                assert!(index < self.targets.len(), "Invalid target index");
                self.targets[index].to_canonical_u64() as u32
            }
            _ => panic!("Invalid data type for U32Target"),
        }
    }
    pub fn resolve_target_array(&self, id: u64) -> Vec<F> {
        let (t, index) = decode_indexed_op_id(id);
        match t {
            DPNBuiltInDataType::BoolArray => {
                assert!(index < self.bool_arrays.len(), "Invalid bool array index");
                self.bool_arrays[index].iter().map(|b| if *b { F::ONE } else { F::ZERO }).collect()
            }
            DPNBuiltInDataType::TargetArray => {
                assert!(index < self.target_arrays.len(), "Invalid target array index");
                self.target_arrays[index].clone()
            }

            DPNBuiltInDataType::U32TargetArray => {
                assert!(index < self.u32_arrays.len(), "Invalid u32 array index");

                self.u32_arrays[index].iter().map(|b| F::from_canonical_u32(*b)).collect()
            }
            _ => panic!("Invalid data type for target array"),
        }
    }
    pub fn resolve_target_array_ref(&self, id: u64, index_id: u64) -> F {
        let (t, index) = decode_indexed_op_id(id);
        //println!("array_data_type: {:?}, arr_index: {}", t, index);
        //println!("in_array_index_target_id: {}",index_id);

        let ind_real = self.resolve_target(index_id);
        //println!("in_array_index_target_id: {} (equals {})",index_id,
        // ind_real.to_canonical_u64());

        match t {
            DPNBuiltInDataType::HashOut => {
                assert!(ind_real.to_canonical_u64() < 4, "Invalid index in hash");
                self.hashes[index][ind_real.to_canonical_u64() as usize]
            }
            DPNBuiltInDataType::HashOut160 => {
                assert!(ind_real.to_canonical_u64() < 5, "Invalid index in hash160");
                F::from_canonical_u32(self.hash160s[index][ind_real.to_canonical_u64() as usize])
            }
            DPNBuiltInDataType::BoolArray => {
                assert!(index < self.bool_arrays.len(), "Invalid bool array index");
                if self.bool_arrays[index][ind_real.to_canonical_u64() as usize] {
                    F::ONE
                } else {
                    F::ZERO
                }
            }
            DPNBuiltInDataType::TargetArray => {
                assert!(index < self.target_arrays.len(), "Invalid target array index");
                self.target_arrays[index][ind_real.to_canonical_u64() as usize]
            }

            DPNBuiltInDataType::U32TargetArray => {
                assert!(index < self.u32_arrays.len(), "Invalid u32 array index");
                F::from_canonical_u32(self.u32_arrays[index][ind_real.to_canonical_u64() as usize])
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
                if self.resolve_bool(id) {
                    F::ONE
                } else {
                    F::ZERO
                }
            }
            DPNBuiltInDataType::U32Target => {
                assert!(
                    ind_real.to_canonical_u64() == 0,
                    "Invalid index {} for scalar U32Target id={}",
                    ind_real.to_canonical_u64(),
                    id
                );
                F::from_canonical_u32(self.resolve_u32(id))
            }
            _ => panic!("Invalid data type for target array"),
        }
    }
    pub fn resolve_bool_array(&self, id: u64) -> Vec<bool> {
        let (t, index) = decode_indexed_op_id(id);
        match t {
            DPNBuiltInDataType::BoolArray => {
                assert!(index < self.bool_arrays.len(), "Invalid bool array index");
                self.bool_arrays[index].clone()
            }
            _ => panic!("Invalid data type for bool array"),
        }
    }
    pub fn resolve_u32_array(&self, id: u64) -> Vec<u32> {
        let (t, index) = decode_indexed_op_id(id);
        match t {
            DPNBuiltInDataType::U32TargetArray => {
                assert!(index < self.u32_arrays.len(), "Invalid u32 array index");
                self.u32_arrays[index].clone()
            }
            _ => panic!("Invalid data type for bool array"),
        }
    }

    #[allow(dead_code)]
    fn print_current_op(&self, op: &DPNIndexedVarDef) {
        match op.data_type {
            DPNBuiltInDataType::Target => println!("d_target[{}] -> {:?}", self.targets.len(), op),
            DPNBuiltInDataType::Bool => println!("d_bool[{}] -> {:?}", self.u32_arrays.len(), op),
            DPNBuiltInDataType::U32Target => println!("d_u32[{}] -> {:?}", self.u32s.len(), op),
            DPNBuiltInDataType::HashOut => println!("d_hashout[{}] -> {:?}", self.hashes.len(), op),
            DPNBuiltInDataType::HashOut160 => println!("d_hash160[{}] -> {:?}", self.hash160s.len(), op),
            DPNBuiltInDataType::TargetArray => println!("d_target_array[{}] -> {:?}", self.target_arrays.len(), op),
            DPNBuiltInDataType::BoolArray => println!("d_bool_array[{}] -> {:?}", self.bool_arrays.len(), op),
            DPNBuiltInDataType::U32TargetArray => println!("d_u32_array[{}] -> {:?}", self.u32_arrays.len(), op),
            DPNBuiltInDataType::Unknown => println!("d_unknown: {:?}", op),
        }
    }

    pub fn process_var_def(&mut self, op: &DPNIndexedVarDef) {
        //self.print_current_op(op);

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
                        let value = self.inputs[index].to_canonical_u64();
                        assert!(value <= 0xffff_ffff, "Invalid u32 input value");
                        out.push(value as u32);
                    }
                    self.set_u32_array_at(op.index, out, "InputTarget(U32TargetArray)");
                }
                _ => {
                    let index = op.inputs[0] as usize;
                    if index >= self.inputs.len() {
                        panic!("Invalid input index");
                    } else {
                        self.set_target_at(op.index, self.inputs[index], "InputTarget(Target)");
                    }
                }
            },
            DPNOpType::Constant => self.set_target_at(op.index, F::from_canonical_u64(op.inputs[0]), "Constant"),
            DPNOpType::ConstantTrue => self.set_bool_at(op.index, true, "ConstantTrue"),
            DPNOpType::ConstantFalse => self.set_bool_at(op.index, false, "ConstantFalse"),
            DPNOpType::Add => {
                let left = self.resolve_target(op.inputs[0]);
                let right = self.resolve_target(op.inputs[1]);
                self.set_target_at(op.index, left + right, "Add");
            }
            DPNOpType::Sub => {
                let left = self.resolve_target(op.inputs[0]);
                let right = self.resolve_target(op.inputs[1]);
                self.set_target_at(op.index, left - right, "Sub");
            }
            DPNOpType::Mul => {
                let left = self.resolve_target(op.inputs[0]);
                let right = self.resolve_target(op.inputs[1]);
                self.set_target_at(op.index, left * right, "Mul");
            }
            DPNOpType::Div => {
                let left = self.resolve_target(op.inputs[0]);
                let right = self.resolve_target(op.inputs[1]);
                self.set_target_at(op.index, left / right, "Div");
            }
            DPNOpType::BoolNot => {
                let left = self.resolve_bool(op.inputs[0]);
                self.set_bool_at(op.index, !left, "BoolNot");
            }
            DPNOpType::BoolAnd => {
                let left = self.resolve_bool(op.inputs[0]);
                let right = self.resolve_bool(op.inputs[1]);
                self.set_bool_at(op.index, left && right, "BoolAnd");
            }
            DPNOpType::BoolOr => {
                let left = self.resolve_bool(op.inputs[0]);
                let right = self.resolve_bool(op.inputs[1]);
                self.set_bool_at(op.index, left || right, "BoolOr");
            }
            DPNOpType::Xor => {
                let left = self.resolve_bool(op.inputs[0]);
                let right = self.resolve_bool(op.inputs[1]);
                self.set_bool_at(op.index, left ^ right, "Xor");
            }
            DPNOpType::Nor => {
                let left = self.resolve_bool(op.inputs[0]);
                let right = self.resolve_bool(op.inputs[1]);
                self.set_bool_at(op.index, !(left || right), "Nor");
            }
            DPNOpType::Eq => {
                let left = self.resolve_target(op.inputs[0]);
                let right = self.resolve_target(op.inputs[1]);
                self.set_bool_at(op.index, left == right, "Eq");
            }
            DPNOpType::Lte => {
                let left = self.resolve_target(op.inputs[0]).to_canonical_u64();
                let right = self.resolve_target(op.inputs[1]).to_canonical_u64();
                self.set_bool_at(op.index, left <= right, "Lte");
            }
            DPNOpType::Gte => {
                let left = self.resolve_target(op.inputs[0]).to_canonical_u64();
                let right = self.resolve_target(op.inputs[1]).to_canonical_u64();
                self.set_bool_at(op.index, left >= right, "Gte");
            }
            DPNOpType::Gt => {
                let left = self.resolve_target(op.inputs[0]).to_canonical_u64();
                let right = self.resolve_target(op.inputs[1]).to_canonical_u64();
                self.set_bool_at(op.index, left > right, "Gt");
            }
            DPNOpType::Lt => {
                let left = self.resolve_target(op.inputs[0]).to_canonical_u64();
                let right = self.resolve_target(op.inputs[1]).to_canonical_u64();
                self.set_bool_at(op.index, left < right, "Lt");
            }
            DPNOpType::SplitBits => {
                let target = self.resolve_target(op.inputs[1]);
                let num_bits = op.inputs[0];
                assert!(num_bits <= 64, "SplitBits: num_bits must be less than 64");

                let actual_target_bits = 64 - target.to_canonical_u64().leading_zeros();
                assert!(actual_target_bits <= num_bits as u32, "SplitBits: target bits must be less than num_bits");

                self.set_bool_array_at(op.index, split_bits(target.to_canonical_u64(), num_bits), "SplitBits");
            }
            DPNOpType::SumBits => {
                assert!(op.inputs.len() <= 64, "Sumbits: can only sum at most 64 bits");
                let sum = op
                    .inputs
                    .iter()
                    .enumerate()
                    .map(|(i, &input)| self.resolve_bool(input) as u64 * (1 << i))
                    .sum::<u64>();

                assert!(sum <= F::ORDER, "SumBits: sum must be less than field order");

                self.set_target_at(op.index, F::from_canonical_u64(sum), "SumBits");
            }
            DPNOpType::TargetAt => {
                let r = self.resolve_target_array_ref(op.inputs[0], op.inputs[1]);
                self.set_target_at(op.index, r, "TargetAt");
            }
            DPNOpType::HashNoPad => {
                let values = self.resolve_targets(&op.inputs);
                let result = PoseidonHash::hash_no_pad(&values);
                if self.should_trace_claim_deposit_hashes() {
                    tracing::info!(
                        op_index = op.index,
                        op_type = "HashNoPad",
                        input_len = values.len(),
                        result = %Self::fmt_hash_elements(&result.elements),
                        "claim_deposit hash trace"
                    );
                }
                self.set_hash_at(op.index, result.elements, "HashNoPad");
            }
            DPNOpType::HashTwoToOne => {
                // Expecting 8 inputs: 4 for left hash, 4 for right hash
                assert_eq!(op.inputs.len(), 8, "HashTwoToOne requires exactly 8 inputs");
                let left = [
                    self.resolve_target(op.inputs[0]),
                    self.resolve_target(op.inputs[1]),
                    self.resolve_target(op.inputs[2]),
                    self.resolve_target(op.inputs[3]),
                ];
                let right = [
                    self.resolve_target(op.inputs[4]),
                    self.resolve_target(op.inputs[5]),
                    self.resolve_target(op.inputs[6]),
                    self.resolve_target(op.inputs[7]),
                ];
                let left_hash = plonky2::hash::hash_types::HashOut { elements: left };
                let right_hash = plonky2::hash::hash_types::HashOut { elements: right };
                let result = PoseidonHash::two_to_one(left_hash, right_hash);
                if self.should_trace_claim_deposit_hashes() {
                    tracing::info!(
                        op_index = op.index,
                        op_type = "HashTwoToOne",
                        left = %Self::fmt_hash_elements(&left_hash.elements),
                        right = %Self::fmt_hash_elements(&right_hash.elements),
                        result = %Self::fmt_hash_elements(&result.elements),
                        "claim_deposit hash trace"
                    );
                }
                self.set_hash_at(op.index, result.elements, "HashTwoToOne");
            }
            DPNOpType::Keccak256 => {
                let values = self.resolve_targets(&op.inputs);
                let mut bytes = Vec::with_capacity(values.len() * 4);
                for value in &values {
                    let limb = value.to_canonical_u64() as u32;
                    bytes.extend_from_slice(&limb.to_be_bytes());
                }
                self.set_u32_array_at(op.index, Self::keccak256_bytes_to_u32x8(&bytes).to_vec(), "Keccak256");
            }
            DPNOpType::HashPad => unimplemented!(),
            DPNOpType::Select => {
                let condition = self.resolve_target(op.inputs[0]);
                let result = if condition.to_canonical_u64() != 0 {
                    self.resolve_target(op.inputs[1])
                } else {
                    self.resolve_target(op.inputs[2])
                };
                self.set_target_at(op.index, result, "Select");
            }
            DPNOpType::Exp => {
                let left = self.resolve_target(op.inputs[0]);
                let right = self.resolve_target(op.inputs[1]);
                self.set_target_at(op.index, left.exp_u64(right.to_canonical_u64()), "Exp");
            }
            DPNOpType::ExpConstantPower => {
                let left = self.resolve_target(op.inputs[0]);
                let (_optype, right) = decode_indexed_op_id(op.inputs[1]);
                self.set_target_at(op.index, left.exp_u64(right as u64), "ExpConstantPower")
            }
            DPNOpType::ExpConstantBase => {
                let (_optype, left) = decode_indexed_op_id(op.inputs[0]);
                let right = self.resolve_target(op.inputs[1]);
                self.set_target_at(
                    op.index,
                    F::from_noncanonical_u64(left as u64).exp_u64(right.to_canonical_u64()),
                    "ExpConstantBase",
                )
            }
            DPNOpType::Mod => {
                let left = self.resolve_target(op.inputs[0]).to_canonical_u64();
                let right = self.resolve_target(op.inputs[1]).to_canonical_u64();
                assert!(right != 0, "Mod by zero");
                self.set_target_at(op.index, F::from_canonical_u64(left % right), "Mod");
            }
            DPNOpType::ModConstantDividend => {
                let (_optype, left) = decode_indexed_op_id(op.inputs[0]);
                let right = self.resolve_target(op.inputs[1]).to_canonical_u64();
                assert!(right != 0, "Mod by zero");
                self.set_target_at(op.index, F::from_canonical_u64((left as u64) % right), "ModConstantDividend");
            }
            DPNOpType::ModConstantDivisor => {
                let left = self.resolve_target(op.inputs[0]).to_canonical_u64();
                let (_optype, right) = decode_indexed_op_id(op.inputs[1]);
                assert!(right != 0, "Mod by zero");
                self.set_target_at(op.index, F::from_canonical_u64(left % (right as u64)), "ModConstantDivisor");
            }
            DPNOpType::DivRem4 => {
                let dividend = self.resolve_target(op.inputs[0]).to_canonical_u64();
                let quotient = F::from_noncanonical_u64(dividend >> 2);
                let remainder = F::from_noncanonical_u64(dividend & 3);
                self.set_target_array_at(op.index, vec![quotient, remainder], "DivRem4");
            }
            DPNOpType::CastU32 => {
                let (t, index) = decode_indexed_op_id(op.inputs[0]);
                let value = match t {
                    DPNBuiltInDataType::U32Target => {
                        assert!(index < self.u32s.len(), "Invalid u32 index");
                        self.u32s[index]
                    }
                    DPNBuiltInDataType::Bool => {
                        assert!(index < self.bools.len(), "Invalid bool index");
                        if self.bools[index] {
                            1
                        } else {
                            0
                        }
                    }
                    DPNBuiltInDataType::Target => {
                        assert!(index < self.targets.len(), "Invalid target index");
                        let value = self.targets[index].to_canonical_u64();
                        assert!(value <= 0xffffffffu64, "Invalid u32 value");
                        (value & 0xffffffffu64) as u32
                    }
                    _ => panic!("Invalid data type for U32Target"),
                };
                self.set_u32_at(op.index, value, "CastU32");
            }
            DPNOpType::U32And => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
                self.set_u32_at(op.index, left & right, "U32And");
            }
            DPNOpType::U32AndConstant => {
                let left = self.resolve_u32(op.inputs[0]);
                let (_optype, right) = decode_indexed_op_id(op.inputs[1]);
                self.set_u32_at(op.index, left & (right as u32), "U32AndConstant");
            }
            DPNOpType::U32Or => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
                self.set_u32_at(op.index, left | right, "U32Or");
            }
            DPNOpType::U32OrConstant => {
                let left = self.resolve_u32(op.inputs[0]);
                let (_optype, right) = decode_indexed_op_id(op.inputs[1]);
                self.set_u32_at(op.index, left | (right as u32), "U32OrConstant");
            }
            DPNOpType::U32Xor => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
                self.set_u32_at(op.index, left ^ right, "U32Xor");
            }
            DPNOpType::U32XorConstant => {
                let left = self.resolve_u32(op.inputs[0]);
                let (_optype, right) = decode_indexed_op_id(op.inputs[1]);
                self.set_u32_at(op.index, left ^ (right as u32), "U32XorConstant");
            }
            DPNOpType::U32ShiftLeft => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
                if right >= 32 {
                    self.set_u32_at(op.index, 0u32, "U32ShiftLeftZero");
                } else {
                    self.set_u32_at(op.index, left << right, "U32ShiftLeft");
                }
            }
            DPNOpType::U32ShiftLeftConstantBitDistance => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
                if right >= 32 {
                    self.set_u32_at(op.index, 0u32, "U32ShiftLeftConstantBitDistanceZero");
                } else {
                    self.set_u32_at(op.index, left << right, "U32ShiftLeftConstantBitDistance");
                }
            }
            DPNOpType::U32ShiftLeftConstantValue => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
                if right >= 32 {
                    self.set_u32_at(op.index, 0u32, "U32ShiftLeftConstantValueZero");
                } else {
                    self.set_u32_at(op.index, left << right, "U32ShiftLeftConstantValue");
                }
            }
            DPNOpType::U32ShiftRight => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
                if right >= 32 {
                    self.set_u32_at(op.index, 0u32, "U32ShiftRightZero");
                } else {
                    self.set_u32_at(op.index, left >> right, "U32ShiftRight");
                }
            }
            DPNOpType::U32ShiftRightConstantBitDistance => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
                if right >= 32 {
                    self.set_u32_at(op.index, 0u32, "U32ShiftRightConstantBitDistanceZero");
                } else {
                    self.set_u32_at(op.index, left >> right, "U32ShiftRightConstantBitDistance");
                }
            }
            DPNOpType::U32ShiftRightConstantValue => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
                if right >= 32 {
                    self.set_u32_at(op.index, 0u32, "U32ShiftRightConstantValueZero");
                } else {
                    self.set_u32_at(op.index, left >> right, "U32ShiftRightConstantValue");
                }
            }
            DPNOpType::CalculateMerkleRoot => unimplemented!(),
            DPNOpType::GetUserId => self.set_target_at(op.index, self.user_id, "GetUserId"),
            DPNOpType::GetContractId => self.set_target_at(op.index, self.contract_id, "GetContractId"),
            DPNOpType::GetCallerContractId => self.set_target_at(op.index, self.caller_contract_id, "GetCallerContractId"),
            DPNOpType::GetCheckpointId => self.set_target_at(op.index, self.checkpoint_id, "GetCheckpointId"),
            DPNOpType::GetNonce => self.set_target_at(op.index, self.nonce, "GetNonce"),
            DPNOpType::GetUserPublicKeyHash => self.set_hash_at(op.index, self.user_public_key, "GetUserPublicKeyHash"),
            DPNOpType::GetSessionProofTreeRoot => self.set_hash_at(op.index, self.session_proof_tree_root, "GetSessionProofTreeRoot"),

            // GetStateQueryResult is deprecated, use GetStateCommandResult instead
            DPNOpType::GetStateQueryResult => unimplemented!("deprecated"),
            DPNOpType::GetStateQueryResultSingle => unimplemented!("deprecated"),

            DPNOpType::GetStateCommandResultHash => unreachable!(),
            DPNOpType::GetStateCommandResultSingle => unreachable!(),
            DPNOpType::GetStateCommandResultArray => unreachable!(),
            DPNOpType::UnaryInverse => {
                let left = self.resolve_target(op.inputs[0]);
                assert_ne!(left, F::ZERO, "Cannot inverse zero");
                self.set_target_at(op.index, left.inverse(), "UnaryInverse");
            }
            DPNOpType::UnaryNegative => {
                let left = self.resolve_target(op.inputs[0]);
                self.set_target_at(op.index, left.neg(), "UnaryNegative");
            }
            DPNOpType::U32InputTarget => {
                let index = op.inputs[0] as usize;
                if index >= self.inputs.len() {
                    panic!("Invalid input index");
                } else {
                    assert!(self.inputs[index].to_canonical_u64() <= 0xffffffffu64, "Invalid u32 input[{:?}]", index);
                    self.set_u32_at(op.index, self.inputs[index].to_canonical_u64() as u32, "U32InputTarget");
                }
            }
            DPNOpType::ConstantU32 => {
                assert!(op.inputs[0] <= 0xffffffffu64, "constant u32 value too large");
                self.set_u32_at(op.index, op.inputs[0] as u32, "ConstantU32");
            }
            DPNOpType::U32Add => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
                assert!(left as u64 + right as u64 <= 0xffffffffu64, "u32 add value too large");
                self.set_u32_at(op.index, left + right, "U32Add");
            }
            DPNOpType::U32Sub => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
                assert!(left > right, "u32 sub value too low");
                self.set_u32_at(op.index, left - right, "U32Sub");
            }
            DPNOpType::U32Mul => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
                assert!(left as u64 * right as u64 <= 0xffffffffu64, "u32 mul value too large");
                self.set_u32_at(op.index, left * right, "U32Mul");
            }
            DPNOpType::U32Div => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
                assert!(right != 0, "u32 div by zero");
                self.set_u32_at(op.index, left / right, "U32Div");
            }
            DPNOpType::CastFelt => {
                let (t, index) = decode_indexed_op_id(op.inputs[0]);
                let value = match t {
                    DPNBuiltInDataType::U32Target => {
                        assert!(index < self.u32s.len(), "Invalid u32 index");

                        self.u32s[index] as u64
                    }
                    DPNBuiltInDataType::Bool => {
                        assert!(index < self.bools.len(), "Invalid bool index");
                        if self.bools[index] {
                            1
                        } else {
                            0
                        }
                    }
                    DPNBuiltInDataType::Target => {
                        assert!(index < self.targets.len(), "Invalid target index");
                        self.targets[index].to_canonical_u64()
                    }
                    _ => panic!("Invalid data type for Target"),
                };
                self.set_target_at(op.index, F::from_canonical_u64(value), "CastFelt");
            }
            DPNOpType::CastBool => {
                let (t, index) = decode_indexed_op_id(op.inputs[0]);
                let value = match t {
                    DPNBuiltInDataType::U32Target => {
                        assert!(index < self.u32s.len(), "Invalid u32 index");
                        assert!(self.u32s[index] <= 1, "Invalid bool value");
                        self.u32s[index] != 0
                    }
                    DPNBuiltInDataType::Bool => {
                        assert!(index < self.bools.len(), "Invalid bool index");
                        self.bools[index]
                    }
                    DPNBuiltInDataType::Target => {
                        assert!(index < self.targets.len(), "Invalid target index");
                        assert!(self.targets[index].to_canonical_u64() <= 1, "Invalid bool value");
                        self.targets[index].to_canonical_u64() != 0
                    }
                    _ => panic!("Invalid data type for Target"),
                };
                self.set_bool_at(op.index, value, "CastBool");
            }
            DPNOpType::BoolInputTarget => {
                let index = op.inputs[0] as usize;
                if index >= self.inputs.len() {
                    panic!("Invalid input index");
                } else {
                    assert!(self.inputs[index].to_canonical_u64() <= 1, "Invalid bool input[{:?}]", index);
                    self.set_bool_at(op.index, self.inputs[index].to_canonical_u64() != 0, "BoolInputTarget");
                }
            }
            DPNOpType::U32Mod => {
                let left = self.resolve_u32(op.inputs[0]);
                let right = self.resolve_u32(op.inputs[1]);
                assert!(right != 0, "u32 mod by zero");
                self.set_u32_at(op.index, left % right, "U32Mod");
            }
            DPNOpType::U32Exp => {
                let left = self.resolve_target(op.inputs[0]);
                let right = self.resolve_target(op.inputs[1]);
                let res = left.exp_u64(right.to_canonical_u64()).to_canonical_u64();
                assert!(res <= 0xffffffffu64, "u32 exp value too large");
                self.set_u32_at(op.index, res as u32, "U32Exp");
            }
            DPNOpType::Secp256k1Verify => {
                // 8 + 8 + 8 + 8 + 8 = 40
                use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature};
                let inputs = self.resolve_targets(&op.inputs);
                assert!(inputs.len() == 36, "Secp256k1Verify input length must be 36");
                let pk_u32 = inputs[0..16]
                    .to_vec()
                    .iter()
                    .map(|k| {
                        assert!(k.to_canonical_u64() < 0xffffffffu64, "secp pk.x must be [u32; 16]");
                        k.to_canonical_u64() as u32
                    })
                    .collect::<Vec<u32>>();
                let pk_x_bytes = pk_u32[0..8].iter().flat_map(|&num| num.to_le_bytes()).rev().collect::<Vec<_>>();
                let pk_y_bytes = pk_u32[8..16].iter().flat_map(|&num| num.to_le_bytes()).rev().collect::<Vec<_>>();
                let mut pk_sec1_bytes = vec![0x04];
                pk_sec1_bytes.extend(pk_x_bytes);
                pk_sec1_bytes.extend(pk_y_bytes);
                let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&pk_sec1_bytes).expect("secp pk must be valid");
                let signature_u32 = inputs[16..32]
                    .to_vec()
                    .iter()
                    .map(|k| {
                        assert!(k.to_canonical_u64() < 0xffffffffu64, "secp signature must be [u32; 16]");
                        k.to_canonical_u64() as u32
                    })
                    .collect::<Vec<u32>>();

                let signature_r_bytes = signature_u32[0..8].iter().flat_map(|&num| num.to_le_bytes()).rev().collect::<Vec<_>>();
                let signature_s_bytes = signature_u32[8..16].iter().flat_map(|&num| num.to_le_bytes()).rev().collect::<Vec<_>>();

                let signature_bytes = signature_r_bytes.iter().chain(signature_s_bytes.iter()).cloned().collect::<Vec<_>>();

                let signature = Signature::from_slice(&signature_bytes).expect("secp signature must be valid");

                let msg_bytes = inputs[32..36]
                    .iter()
                    .flat_map(|&num| num.to_canonical_u64().to_le_bytes())
                    .rev()
                    .collect::<Vec<_>>();

                match vk.verify_prehash(&msg_bytes, &signature) {
                    Ok(_) => self.set_bool_at(op.index, true, "Secp256k1VerifyOk"),
                    Err(_) => self.set_bool_at(op.index, false, "Secp256k1VerifyErr"),
                }
            }
        }
    }
}

fn split_bits(x: u64, num_bits: u64) -> Vec<bool> {
    let mut result = vec![false; num_bits as usize];
    for i in 0..num_bits {
        result[i as usize] = ((x >> i) & 1) != 0;
    }
    result
}

#[cfg(test)]
mod tests {
    use alloy_primitives::FixedBytes;
    use alloy_sol_types::SolValue;
    use plonky2::field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    };
    use tiny_keccak::{Hasher as _, Keccak};

    use super::*;
    use crate::dpn::ops::op_types::{encode_indexed_op_id, DPNBuiltInDataType};

    fn mk_exec(inputs: Vec<u64>) -> SimpleDPNExecutor<GoldilocksField> {
        let felt_inputs = inputs.into_iter().map(GoldilocksField::from_canonical_u64).collect::<Vec<_>>();
        SimpleDPNExecutor::new_with_contract_ctx(
            felt_inputs,
            GoldilocksField::ZERO,
            GoldilocksField::ZERO,
            GoldilocksField::ZERO,
            GoldilocksField::ZERO,
            GoldilocksField::ZERO,
            [GoldilocksField::ZERO; 4],
            [GoldilocksField::ZERO; 4],
        )
    }

    fn keccak_digest_bytes_to_u32x8(bytes: &[u8]) -> [u32; 8] {
        let mut digest = [0u8; 32];
        let mut keccak = Keccak::v256();
        keccak.update(bytes);
        keccak.finalize(&mut digest);
        let mut out = [0u32; 8];
        for i in 0..8 {
            out[i] = u32::from_be_bytes(digest[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        out
    }

    fn vm_keccak_words_u32_be_bytes(words: &[u64]) -> [u32; 8] {
        let mut bytes = Vec::with_capacity(words.len() * 4);
        for w in words {
            bytes.extend_from_slice(&(*w as u32).to_be_bytes());
        }
        keccak_digest_bytes_to_u32x8(&bytes)
    }

    fn bytes32_hex_to_u32x8_be_limbs(hex32: &str) -> [u32; 8] {
        let s = hex32.strip_prefix("0x").unwrap_or(hex32);
        assert_eq!(s.len(), 64);
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            let part = &s[i * 2..i * 2 + 2];
            bytes[i] = u8::from_str_radix(part, 16).unwrap();
        }
        let mut out = [0u32; 8];
        for i in 0..8 {
            out[i] = u32::from_be_bytes(bytes[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        out
    }

    #[test]
    fn input_u32x8_parameter_supports_target_at() {
        let mut exec = mk_exec(vec![10, 11, 12, 13, 14, 15, 16, 17]);

        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::U32TargetArray,
            index: 0,
            op_type: DPNOpType::InputTarget,
            inputs: (0..8).map(|i| i as u64).collect(),
        });
        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 0,
            op_type: DPNOpType::Constant,
            inputs: vec![3],
        });
        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 1,
            op_type: DPNOpType::TargetAt,
            inputs: vec![
                encode_indexed_op_id(DPNBuiltInDataType::U32TargetArray, 0),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 0),
            ],
        });

        assert_eq!(
            exec.targets.last().unwrap().to_canonical_u64(),
            13,
            "TargetAt should read 4th limb from [u32;8] parameter",
        );
    }

    #[test]
    fn sparse_u32_array_indices_are_addressable_by_op_index() {
        let mut exec = mk_exec(vec![100, 101, 102, 103, 104, 105, 106, 107, 200, 201, 202, 203, 204, 205, 206, 207]);

        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::U32TargetArray,
            index: 0,
            op_type: DPNOpType::InputTarget,
            inputs: (0..8).map(|i| i as u64).collect(),
        });
        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::U32TargetArray,
            index: 1,
            op_type: DPNOpType::InputTarget,
            inputs: (8..16).map(|i| i as u64).collect(),
        });
        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 0,
            op_type: DPNOpType::Constant,
            inputs: vec![0],
        });
        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 1,
            op_type: DPNOpType::Constant,
            inputs: vec![1],
        });

        let a = exec.resolve_target_array_ref(
            encode_indexed_op_id(DPNBuiltInDataType::U32TargetArray, 0),
            encode_indexed_op_id(DPNBuiltInDataType::Target, 0),
        );
        let b = exec.resolve_target_array_ref(
            encode_indexed_op_id(DPNBuiltInDataType::U32TargetArray, 1),
            encode_indexed_op_id(DPNBuiltInDataType::Target, 1),
        );
        assert_eq!(a.to_canonical_u64(), 100);
        assert_eq!(b.to_canonical_u64(), 201);
    }

    #[test]
    #[should_panic(expected = "Conflicting u32 array assignment")]
    fn conflicting_u32_array_writes_panic() {
        let mut exec = mk_exec(vec![1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 13, 14, 15, 16, 17, 18]);
        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::U32TargetArray,
            index: 0,
            op_type: DPNOpType::InputTarget,
            inputs: (0..8).map(|i| i as u64).collect(),
        });
        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::U32TargetArray,
            index: 0,
            op_type: DPNOpType::InputTarget,
            inputs: (8..16).map(|i| i as u64).collect(),
        });
    }

    #[test]
    fn external_target_results_are_bound_by_definition_index() {
        let mut exec = mk_exec(vec![]);

        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 0,
            op_type: DPNOpType::Constant,
            inputs: vec![7],
        });
        exec.push_external_target(1, GoldilocksField::from_canonical_u64(42));

        assert_eq!(
            exec.resolve_target(encode_indexed_op_id(DPNBuiltInDataType::Target, 0))
                .to_canonical_u64(),
            7
        );
        assert_eq!(
            exec.resolve_target(encode_indexed_op_id(DPNBuiltInDataType::Target, 1))
                .to_canonical_u64(),
            42
        );
    }

    #[test]
    fn external_array_results_are_bound_by_definition_index() {
        let mut exec = mk_exec(vec![]);

        exec.push_external_target_array(0, vec![GoldilocksField::from_canonical_u64(10), GoldilocksField::from_canonical_u64(11)]);
        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 0,
            op_type: DPNOpType::Constant,
            inputs: vec![1],
        });
        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 1,
            op_type: DPNOpType::TargetAt,
            inputs: vec![
                encode_indexed_op_id(DPNBuiltInDataType::TargetArray, 0),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 0),
            ],
        });

        assert_eq!(
            exec.resolve_target(encode_indexed_op_id(DPNBuiltInDataType::Target, 1))
                .to_canonical_u64(),
            11
        );
    }

    #[test]
    fn add_with_contract_state_array_reads_correct_slots() {
        let mut exec = mk_exec(vec![11, 17, 3, 5]);

        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::U32TargetArray,
            index: 0,
            op_type: DPNOpType::InputTarget,
            inputs: vec![0, 1],
        });
        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::U32TargetArray,
            index: 1,
            op_type: DPNOpType::InputTarget,
            inputs: vec![2, 3],
        });
        exec.push_external_target_array(0, vec![GoldilocksField::from_canonical_u64(19), GoldilocksField::from_canonical_u64(23)]);

        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 0,
            op_type: DPNOpType::Constant,
            inputs: vec![0],
        });
        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 1,
            op_type: DPNOpType::Constant,
            inputs: vec![1],
        });

        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 2,
            op_type: DPNOpType::TargetAt,
            inputs: vec![
                encode_indexed_op_id(DPNBuiltInDataType::U32TargetArray, 0),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 0),
            ],
        });
        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 3,
            op_type: DPNOpType::TargetAt,
            inputs: vec![
                encode_indexed_op_id(DPNBuiltInDataType::U32TargetArray, 1),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 0),
            ],
        });
        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 4,
            op_type: DPNOpType::Sub,
            inputs: vec![
                encode_indexed_op_id(DPNBuiltInDataType::Target, 2),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 3),
            ],
        });

        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 5,
            op_type: DPNOpType::TargetAt,
            inputs: vec![
                encode_indexed_op_id(DPNBuiltInDataType::U32TargetArray, 0),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 1),
            ],
        });
        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 6,
            op_type: DPNOpType::TargetAt,
            inputs: vec![
                encode_indexed_op_id(DPNBuiltInDataType::U32TargetArray, 1),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 1),
            ],
        });
        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 7,
            op_type: DPNOpType::Sub,
            inputs: vec![
                encode_indexed_op_id(DPNBuiltInDataType::Target, 5),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 6),
            ],
        });

        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 8,
            op_type: DPNOpType::TargetAt,
            inputs: vec![
                encode_indexed_op_id(DPNBuiltInDataType::TargetArray, 0),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 0),
            ],
        });
        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 9,
            op_type: DPNOpType::TargetAt,
            inputs: vec![
                encode_indexed_op_id(DPNBuiltInDataType::TargetArray, 0),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 1),
            ],
        });

        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 10,
            op_type: DPNOpType::Add,
            inputs: vec![
                encode_indexed_op_id(DPNBuiltInDataType::Target, 4),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 7),
            ],
        });
        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 11,
            op_type: DPNOpType::Add,
            inputs: vec![
                encode_indexed_op_id(DPNBuiltInDataType::Target, 8),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 9),
            ],
        });
        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 12,
            op_type: DPNOpType::Add,
            inputs: vec![
                encode_indexed_op_id(DPNBuiltInDataType::Target, 10),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 11),
            ],
        });

        assert_eq!(
            exec.resolve_target(encode_indexed_op_id(DPNBuiltInDataType::Target, 12))
                .to_canonical_u64(),
            62,
            "a[0]-b[0] + a[1]-b[1] + c[0] + c[1] should equal 62",
        );
    }

    #[test]
    fn old_push_semantics_put_external_target_in_physical_slot_not_logical_index() {
        let mut exec = mk_exec(vec![]);

        // Intended logical binding:
        //   external result -> Target index 1
        //
        // Old behavior did this:
        exec.targets.push(GoldilocksField::from_canonical_u64(42));
        // So the value lands in physical slot 0, not logical index 1.
        assert_eq!(exec.targets.len(), 1);
        assert_eq!(exec.targets[0].to_canonical_u64(), 42);

        let caught = std::panic::catch_unwind(|| exec.resolve_target(encode_indexed_op_id(DPNBuiltInDataType::Target, 1)));
        assert!(
            caught.is_err(),
            "with old push semantics, resolving logical Target[1] should fail because only physical slot 0 was populated"
        );
    }

    #[test]
    fn old_push_semantics_put_external_array_in_physical_slot_not_logical_index() {
        let mut exec = mk_exec(vec![]);

        // Intended logical binding:
        //   external result -> TargetArray index 1
        //
        // Old behavior did this:
        exec.target_arrays
            .push(vec![GoldilocksField::from_canonical_u64(19), GoldilocksField::from_canonical_u64(23)]);
        // So the array lands in physical slot 0, not logical index 1.
        assert_eq!(exec.target_arrays.len(), 1);
        assert_eq!(exec.target_arrays[0][0].to_canonical_u64(), 19);
        assert_eq!(exec.target_arrays[0][1].to_canonical_u64(), 23);

        exec.process_var_def(&DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Target,
            index: 0,
            op_type: DPNOpType::Constant,
            inputs: vec![0],
        });

        let caught = std::panic::catch_unwind(|| {
            exec.resolve_target_array_ref(
                encode_indexed_op_id(DPNBuiltInDataType::TargetArray, 1),
                encode_indexed_op_id(DPNBuiltInDataType::Target, 0),
            )
        });
        assert!(
            caught.is_err(),
            "with old push semantics, resolving logical TargetArray[1] should fail because only physical slot 0 was populated"
        );
    }

    #[test]
    fn keccak_two_to_one_matches_abi_encode_packed_bytes32_pair() {
        // Two random bytes32 values represented as u32 limbs (same layout used in CLI
        // helpers).
        let left = bytes32_hex_to_u32x8_be_limbs("0xdacbc08f57113157b1caed6257112dec8fc0cbdaaf661252a0216b1c95d5ed65");
        let right = bytes32_hex_to_u32x8_be_limbs("0x0000000000000000000000000000000000000000000000000000000000000000");

        // Expected EVM-style parent hash = keccak(left_bytes || right_bytes), 64 bytes
        // total.
        let mut left_bytes = Vec::with_capacity(32);
        for limb in left {
            left_bytes.extend_from_slice(&limb.to_be_bytes());
        }
        let mut right_bytes = Vec::with_capacity(32);
        for limb in right {
            right_bytes.extend_from_slice(&limb.to_be_bytes());
        }
        let mut expected_input = left_bytes.clone();
        expected_input.extend_from_slice(&right_bytes);
        let expected = keccak_digest_bytes_to_u32x8(&expected_input);

        // VM Keccak op now treats each Felt as one u32 limb (4 bytes BE),
        // so 16 limbs map exactly to 64 bytes = bytes32 || bytes32.
        let wrong_words: Vec<u64> = left.into_iter().chain(right.into_iter()).map(|x| x as u64).collect();
        let got = vm_keccak_words_u32_be_bytes(&wrong_words);
        assert_eq!(got, expected);
    }

    #[test]
    fn keccak_two_u32_matches_alloy_packed_uint32_pair() {
        let a: u32 = 0x11223344;
        let b: u32 = 0xa1b2c3d4;

        let got = vm_keccak_words_u32_be_bytes(&[a as u64, b as u64]);

        let packed = (a, b).abi_encode_packed();
        let expected = keccak_digest_bytes_to_u32x8(&packed);

        assert_eq!(got, expected);
    }

    #[test]
    fn keccak_two_u32_differs_from_alloy_packed_bytes4_le_pair() {
        let a: u32 = 0x11223344;
        let b: u32 = 0xa1b2c3d4;

        let got = vm_keccak_words_u32_be_bytes(&[a as u64, b as u64]);

        let packed_bytes4_le = (FixedBytes::<4>::from(a.to_le_bytes()), FixedBytes::<4>::from(b.to_le_bytes())).abi_encode_packed();
        let expected_bytes4_le = keccak_digest_bytes_to_u32x8(&packed_bytes4_le);

        assert_ne!(got, expected_bytes4_le);
    }
}
