use core::panic;
use std::ops::Neg;

use k256::ecdsa::Signature;
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    hash::poseidon::PoseidonHash,
    plonk::config::{GenericHashOut, Hasher},
};
use tiny_keccak::{Hasher as _, Keccak};

use super::traits::{ContextEval, ContextInput, EvalCache};
use crate::dpn::ops::{op_types::DPNOpType, sym_felt::SymFeltRef, sym_felt_store::SymFeltStore};
fn split_bits(x: u64, num_bits: u64) -> Vec<u64> {
    let mut result = vec![0u64; num_bits as usize];
    for i in 0..num_bits {
        result[i as usize] = (x >> i) & 1;
    }
    result
}
fn sum_bits(bits: &[u64]) -> u64 {
    assert!(bits.len() <= 64, "cannot sum more than 64 bits");
    let result = bits.iter().fold(0, |acc, x| acc + x);
    GoldilocksField::from_noncanonical_u64(result).to_canonical_u64()
}

fn keccak_words_u32_be_to_u32_vec(words: &[u64]) -> Vec<u32> {
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for word in words {
        bytes.extend_from_slice(&(*word as u32).to_be_bytes());
    }
    let mut digest = [0u8; 32];
    let mut keccak = Keccak::v256();
    keccak.update(&bytes);
    keccak.finalize(&mut digest);

    digest
        .chunks_exact(4)
        .take(8)
        .map(|chunk| {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(chunk);
            u32::from_be_bytes(bytes)
        })
        .collect()
}
trait EvalHelpers: ContextEval {
    fn resolve_binary_felt_args<I: ContextInput, C: EvalCache>(&self, parent: SymFeltRef, input: &I, cache: &mut C) -> (u64, u64);
    fn resolve_unary_felt_arg<I: ContextInput, C: EvalCache>(&self, parent: SymFeltRef, input: &I, cache: &mut C) -> u64;
    fn resolve_array_args<I: ContextInput, C: EvalCache>(&self, parent: SymFeltRef, input: &I, cache: &mut C) -> Vec<u64>;
    fn resolve_binary_felt_args_gl<I: ContextInput, C: EvalCache>(
        &self,
        parent: SymFeltRef,
        input: &I,
        cache: &mut C,
    ) -> (GoldilocksField, GoldilocksField) {
        let (a, b) = self.resolve_binary_felt_args(parent, input, cache);
        (GoldilocksField::from_noncanonical_u64(a), GoldilocksField::from_noncanonical_u64(b))
    }
    fn resolve_unary_felt_arg_gl<I: ContextInput, C: EvalCache>(&self, parent: SymFeltRef, input: &I, cache: &mut C) -> GoldilocksField {
        let resolved = self.resolve_unary_felt_arg(parent, input, cache);
        GoldilocksField::from_noncanonical_u64(resolved)
    }
    fn resolve_array_args_gl<I: ContextInput, C: EvalCache>(&self, parent: SymFeltRef, input: &I, cache: &mut C) -> Vec<GoldilocksField> {
        let resolved = self.resolve_array_args(parent, input, cache);
        resolved.iter().map(|x| GoldilocksField::from_noncanonical_u64(*x)).collect()
    }
}
impl EvalHelpers for SymFeltStore {
    fn resolve_binary_felt_args<I: ContextInput, C: EvalCache>(&self, parent: SymFeltRef, input: &I, cache: &mut C) -> (u64, u64) {
        let resolved = &self.get(parent).inputs;
        assert_eq!(resolved.len(), 2);
        let left = self.resolve_felt_ref_cached(resolved[0], input, cache);
        let right = self.resolve_felt_ref_cached(resolved[1], input, cache);
        (left, right)
    }
    fn resolve_unary_felt_arg<I: ContextInput, C: EvalCache>(&self, parent: SymFeltRef, input: &I, cache: &mut C) -> u64 {
        let resolved = &self.get(parent).inputs;
        assert_eq!(resolved.len(), 1);
        self.resolve_felt_ref_cached(resolved[0], input, cache)
    }

    fn resolve_array_args<I: ContextInput, C: EvalCache>(&self, parent: SymFeltRef, input: &I, cache: &mut C) -> Vec<u64> {
        let resolved = &self.get(parent).inputs;
        resolved
            .iter()
            .map(|felt_ref| self.resolve_felt_ref_cached(*felt_ref, input, cache))
            .collect()
    }
}
impl ContextEval for SymFeltStore {
    fn resolve_felt_ref_cached<I: ContextInput, C: EvalCache>(&self, felt_ref: SymFeltRef, input: &I, cache: &mut C) -> u64 {
        if felt_ref.is_constant_type() {
            felt_ref.get_constant_value()
        } else if cache.contains(felt_ref) {
            cache.get(felt_ref)
        } else {
            let op_type = felt_ref.get_op_type();
            let result = match op_type {
                DPNOpType::InputTarget => input.get_input(felt_ref.get_input_index()),
                DPNOpType::Constant => felt_ref.get_constant_value(),
                DPNOpType::ConstantTrue => 1,
                DPNOpType::ConstantFalse => 0,
                DPNOpType::Add => {
                    let (a, b) = self.resolve_binary_felt_args_gl(felt_ref, input, cache);
                    (a + b).to_canonical_u64()
                }
                DPNOpType::Sub => {
                    let (a, b) = self.resolve_binary_felt_args_gl(felt_ref, input, cache);
                    (a - b).to_canonical_u64()
                }
                DPNOpType::Mul => {
                    let (a, b) = self.resolve_binary_felt_args_gl(felt_ref, input, cache);
                    (a * b).to_canonical_u64()
                }
                DPNOpType::Div => {
                    let (a, b) = self.resolve_binary_felt_args_gl(felt_ref, input, cache);
                    (a / b).to_canonical_u64()
                }
                DPNOpType::BoolNot => (self.resolve_unary_felt_arg(felt_ref, input, cache) == 0) as u64,
                DPNOpType::BoolAnd => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    ((a != 0) && (b != 0)) as u64
                }
                DPNOpType::BoolOr => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    ((a != 0) || (b != 0)) as u64
                }
                DPNOpType::Xor => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    (a ^ b) & 0xFFFFFFFFu64
                }
                DPNOpType::Nor => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    (!(a | b)) & 0xFFFFFFFFu64
                }
                DPNOpType::Eq => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    (a == b) as u64
                }
                DPNOpType::Lte => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    (a <= b) as u64
                }
                DPNOpType::Gte => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    (a >= b) as u64
                }
                DPNOpType::Gt => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    (a > b) as u64
                }
                DPNOpType::Lt => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    (a < b) as u64
                }
                DPNOpType::SplitBits => panic!("you cannot directly evaluate SumBits"),
                DPNOpType::SumBits => sum_bits(&self.resolve_array_args(felt_ref, input, cache)),
                DPNOpType::TargetAt => {
                    let base = &self.get(felt_ref).inputs;
                    let index = self.resolve_felt_ref_cached(base[1], input, cache);
                    let array = self.resolve_array_ref_cached(base[0], input, cache);
                    assert!(index < array.len() as u64, "index out of bounds");
                    array[index as usize]
                }
                DPNOpType::HashNoPad => panic!("you cannot directly evaluate HashNoPad"),
                DPNOpType::HashTwoToOne => panic!("you cannot directly evaluate HashTwoToOne"),
                DPNOpType::Keccak256 => panic!("you cannot directly evaluate Keccak256"),
                DPNOpType::HashPad => panic!("you cannot directly evaluate HashPad"),
                DPNOpType::Select => {
                    let args = self.resolve_array_args(felt_ref, input, cache);
                    if args[0] != 0 {
                        args[1]
                    } else {
                        args[2]
                    }
                }
                DPNOpType::Exp => {
                    let (base, exponent) = self.resolve_binary_felt_args_gl(felt_ref, input, cache);
                    base.exp_u64(exponent.to_canonical_u64()).to_canonical_u64()
                }
                DPNOpType::ExpConstantPower => panic!("ExpConstantPower is not implemented"),
                DPNOpType::ExpConstantBase => panic!("ExpConstantBase is not implemented"),
                DPNOpType::Mod => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    a % b
                }
                DPNOpType::ModConstantDividend => panic!("ModConstantDividend is not implemented"),
                DPNOpType::ModConstantDivisor => panic!("ModConstantDivisor is not implemented"),
                DPNOpType::DivRem4 => {
                    todo!("DivRem4 is not implemented");
                }
                DPNOpType::CastU32 => {
                    let value = self.resolve_unary_felt_arg(felt_ref, input, cache);
                    assert!(value < 0xffffffffu64, "invalid u32 value");
                    value & 0xFFFFFFFFu64
                }
                DPNOpType::U32And => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    (a & b) & 0xFFFFFFFFu64
                }
                DPNOpType::U32AndConstant => todo!("U32AndConstant is not implemented"),
                DPNOpType::U32Or => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    (a | b) & 0xFFFFFFFFu64
                }
                DPNOpType::U32OrConstant => todo!("U32OrConstant is not implemented"),
                DPNOpType::U32Xor => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    (a ^ b) & 0xFFFFFFFFu64
                }
                DPNOpType::U32XorConstant => todo!("U32XorConstant is not implemented"),
                DPNOpType::U32ShiftLeft => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    (a << b) & 0xFFFFFFFFu64
                }
                DPNOpType::U32ShiftLeftConstantBitDistance => todo!("U32ShiftLeftConstantBitDistance is not implemented"),
                DPNOpType::U32ShiftLeftConstantValue => todo!("U32ShiftLeftConstantValue is not implemented"),
                DPNOpType::U32ShiftRight => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    (a >> b) & 0xFFFFFFFFu64
                }
                DPNOpType::U32ShiftRightConstantBitDistance => todo!("U32ShiftLeftConstantValue is not implemented"),
                DPNOpType::U32ShiftRightConstantValue => todo!("U32ShiftLeftConstantValue is not implemented"),
                DPNOpType::CalculateMerkleRoot => todo!("CalculateMerkleRoot is not implemented"),
                DPNOpType::GetUserId => input.get_user_id(),
                DPNOpType::GetContractId => input.get_contract_id(),
                DPNOpType::GetCallerContractId => input.get_caller_contract_id(),
                DPNOpType::GetCheckpointId => input.get_checkpoint_id(),
                DPNOpType::GetNonce => input.get_user_nonce(),
                DPNOpType::GetUserPublicKeyHash => todo!(),
                DPNOpType::GetSessionProofTreeRoot => {
                    panic!("GetSessionProofTreeRoot is hash-typed and should not be resolved as a felt")
                }
                DPNOpType::GetStateQueryResult => todo!(),
                DPNOpType::GetStateQueryResultSingle => todo!(),
                DPNOpType::UnaryInverse => self.resolve_unary_felt_arg_gl(felt_ref, input, cache).inverse().to_canonical_u64(),
                DPNOpType::UnaryNegative => self.resolve_unary_felt_arg_gl(felt_ref, input, cache).neg().to_canonical_u64(),
                DPNOpType::GetStateCommandResultHash => todo!(),
                DPNOpType::GetStateCommandResultSingle => todo!(),
                DPNOpType::GetStateCommandResultArray => todo!(),
                DPNOpType::U32InputTarget => input.get_input(felt_ref.get_input_index()),
                DPNOpType::ConstantU32 => felt_ref.get_constant_value(),
                DPNOpType::U32Add => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    assert!(a < 0xffffffffu64, "a is too large");
                    assert!(b < 0xffffffffu64, "b is too large");
                    assert!(a + b < 0xffffffffu64, "a + b is too large");
                    (a + b) & 0xffffffffu64
                }
                DPNOpType::U32Sub => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    assert!(a < 0xffffffffu64, "a is too large");
                    assert!(b < 0xffffffffu64, "b is too large");
                    assert!(a > b, "a - b < 0");
                    (a - b) & 0xffffffffu64
                }
                DPNOpType::U32Mul => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    assert!(a < 0xffffffffu64, "a is too large");
                    assert!(b < 0xffffffffu64, "b is too large");
                    assert!(a * b < 0xffffffffu64, "a * b is too large");
                    (a * b) & 0xffffffffu64
                }
                DPNOpType::U32Div => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    assert!(a < 0xffffffffu64, "a is too large");
                    assert!(b < 0xffffffffu64, "b is too large");
                    assert!(a / b < 0xffffffffu64, "a / b is too large");
                    (a / b) & 0xffffffffu64
                }
                DPNOpType::CastFelt => {
                    let value = self.resolve_unary_felt_arg(felt_ref, input, cache);
                    value
                }
                DPNOpType::CastBool => {
                    let value = self.resolve_unary_felt_arg(felt_ref, input, cache);
                    assert!(value <= 1, "bool value must be 0 or 1");
                    (value != 0) as u64
                }
                DPNOpType::BoolInputTarget => input.get_input(felt_ref.get_input_index()),
                DPNOpType::U32Mod => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    assert!(b != 0, "b must be non-zero");
                    a % b
                }
                DPNOpType::U32Exp => {
                    let (base, exponent) = self.resolve_binary_felt_args_gl(felt_ref, input, cache);
                    assert!(base.to_canonical_u64() < 0xffffffffu64, "a is too large");
                    assert!(exponent.to_canonical_u64() < 0xffffffffu64, "b is too large");

                    let res = base.exp_u64(exponent.to_canonical_u64()).to_canonical_u64();
                    assert!(res < 0xffffffffu64, "u32 exp result is too large");
                    res
                }
                DPNOpType::Secp256k1Verify => {
                    use k256::ecdsa::signature::hazmat::PrehashVerifier;
                    let inputs = self.resolve_array_args(felt_ref, input, cache);
                    assert!(inputs.len() == 36, "Secp256k1Verify input length must be 36");
                    let pk_u32 = inputs[0..16]
                        .to_vec()
                        .iter()
                        .map(|k| {
                            assert!(*k < 0xffffffffu64, "secp pk.x must be [u32; 16]");
                            *k as u32
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
                            assert!(*k < 0xffffffffu64, "secp signature must be [u32; 16]");
                            *k as u32
                        })
                        .collect::<Vec<u32>>();

                    let signature_r_bytes = signature_u32[0..8].iter().flat_map(|&num| num.to_le_bytes()).rev().collect::<Vec<_>>();
                    let signature_s_bytes = signature_u32[8..16].iter().flat_map(|&num| num.to_le_bytes()).rev().collect::<Vec<_>>();

                    let signature_bytes = signature_r_bytes.iter().chain(signature_s_bytes.iter()).cloned().collect::<Vec<_>>();

                    let signature = Signature::from_slice(&signature_bytes).expect("secp signature must be valid");

                    let msg_bytes = inputs[32..36].iter().flat_map(|&num| num.to_le_bytes()).rev().collect::<Vec<_>>();

                    match vk.verify_prehash(&msg_bytes, &signature) {
                        Ok(_) => 1,
                        Err(_) => 0,
                    }
                }
            };
            result
        }
    }

    fn resolve_array_ref_cached<I: ContextInput, C: EvalCache>(&self, felt_ref: SymFeltRef, input: &I, cache: &mut C) -> Box<Vec<u64>> {
        if cache.contains_arr(felt_ref) {
            cache.get_arr_ref(felt_ref)
        } else {
            let result = match felt_ref.get_op_type() {
                DPNOpType::SplitBits => {
                    let (x, num_bits) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    let bits = split_bits(x, num_bits);
                    bits
                }
                DPNOpType::HashNoPad => {
                    let data = self.resolve_array_args_gl(felt_ref, input, cache);
                    let result = PoseidonHash::hash_no_pad(&data).to_vec();
                    result.iter().map(|x| x.to_canonical_u64()).collect()
                }
                DPNOpType::HashTwoToOne => {
                    let inputs = self.resolve_array_args_gl(felt_ref, input, cache);
                    assert_eq!(inputs.len(), 8, "HashTwoToOne requires exactly 8 inputs");
                    let left = plonky2::hash::hash_types::HashOut {
                        elements: [inputs[0], inputs[1], inputs[2], inputs[3]],
                    };
                    let right = plonky2::hash::hash_types::HashOut {
                        elements: [inputs[4], inputs[5], inputs[6], inputs[7]],
                    };
                    let result = PoseidonHash::two_to_one(left, right);
                    result.elements.iter().map(|x| x.to_canonical_u64()).collect()
                }
                DPNOpType::Keccak256 => {
                    let data = self.resolve_array_args(felt_ref, input, cache);
                    keccak_words_u32_be_to_u32_vec(&data).iter().map(|x| *x as u64).collect()
                }
                DPNOpType::HashPad => {
                    let data = self.resolve_array_args_gl(felt_ref, input, cache);
                    let result = PoseidonHash::hash_pad(&data).to_vec();
                    result.iter().map(|x| x.to_canonical_u64()).collect()
                }
                DPNOpType::GetUserPublicKeyHash => input.get_user_public_key_hash().to_vec(),
                DPNOpType::GetSessionProofTreeRoot => input.get_session_proof_tree_root().to_vec(),
                _ => panic!("you cannot directly evaluate an array ref"),
            };

            cache.insert_arr(felt_ref, result);
            cache.get_arr_ref(felt_ref)
        }
    }
}
