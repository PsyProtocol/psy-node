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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpn::eval::{cache::SimpleEvalCache, simple::DummyContextEvalInput};
    use crate::dpn::ops::op_types::DPNBuiltInDataType;
    use psy_config::network_constants::DEFAULT_CALLER_CONTRACT_ID_U64;

    fn op(store: &mut SymFeltStore, op_type: DPNOpType, inputs: Vec<SymFeltRef>) -> SymFeltRef {
        store.insert(crate::dpn::ops::sym_felt::SymFeltRefValue { op_type, const_param: 0, inputs })
    }

    fn resolve(store: &SymFeltStore, reference: SymFeltRef) -> u64 {
        store.resolve_felt_ref_cached(reference, &DummyContextEvalInput::new(vec![9, 3]), &mut SimpleEvalCache::new())
    }

    fn insert_and_resolve(store: &mut SymFeltStore, op_type: DPNOpType, inputs: Vec<SymFeltRef>) -> u64 {
        let reference = op(store, op_type, inputs);
        resolve(store, reference)
    }

    #[test]
    fn evaluates_scalar_arithmetic_boolean_comparison_and_context_ops() {
        let mut store = SymFeltStore::new();
        let a = SymFeltRef::new_constant(9);
        let b = SymFeltRef::new_constant(3);
        let cases = [
            (DPNOpType::Add, 12), (DPNOpType::Sub, 6), (DPNOpType::Mul, 27), (DPNOpType::Div, 3),
            (DPNOpType::BoolAnd, 1), (DPNOpType::BoolOr, 1), (DPNOpType::Xor, 10), (DPNOpType::Nor, 4_294_967_284),
            (DPNOpType::Eq, 0), (DPNOpType::Lte, 0), (DPNOpType::Gte, 1), (DPNOpType::Gt, 1),
            (DPNOpType::Lt, 0), (DPNOpType::Exp, 729), (DPNOpType::Mod, 0), (DPNOpType::U32And, 1),
            (DPNOpType::U32Or, 11), (DPNOpType::U32Xor, 10), (DPNOpType::U32ShiftLeft, 72),
            (DPNOpType::U32ShiftRight, 1), (DPNOpType::U32Add, 12), (DPNOpType::U32Sub, 6),
            (DPNOpType::U32Mul, 27), (DPNOpType::U32Div, 3), (DPNOpType::U32Mod, 0), (DPNOpType::U32Exp, 729),
        ];
        for (kind, expected) in cases {
            assert_eq!(insert_and_resolve(&mut store, kind, vec![a, b]), expected, "{kind}");
        }
        assert_eq!(insert_and_resolve(&mut store, DPNOpType::BoolNot, vec![SymFeltRef::new_constant(0)]), 1);
        let inverse = insert_and_resolve(&mut store, DPNOpType::UnaryInverse, vec![a]);
        assert_eq!(GoldilocksField::from_noncanonical_u64(9).inverse().to_canonical_u64(), inverse);
        let negative = insert_and_resolve(&mut store, DPNOpType::UnaryNegative, vec![a]);
        assert_eq!(GoldilocksField::from_noncanonical_u64(9).neg().to_canonical_u64(), negative);
        assert_eq!(insert_and_resolve(&mut store, DPNOpType::CastU32, vec![a]), 9);
        assert_eq!(insert_and_resolve(&mut store, DPNOpType::CastFelt, vec![a]), 9);
        assert_eq!(insert_and_resolve(&mut store, DPNOpType::CastBool, vec![SymFeltRef::new_constant(1)]), 1);
        assert_eq!(insert_and_resolve(&mut store, DPNOpType::Select, vec![SymFeltRef::new_constant(1), a, b]), 9);
        assert_eq!(insert_and_resolve(&mut store, DPNOpType::GetUserId, vec![]), 0);
        assert_eq!(insert_and_resolve(&mut store, DPNOpType::GetContractId, vec![]), 0);
        assert_eq!(insert_and_resolve(&mut store, DPNOpType::GetCallerContractId, vec![]), DEFAULT_CALLER_CONTRACT_ID_U64);
        assert_eq!(insert_and_resolve(&mut store, DPNOpType::GetCheckpointId, vec![]), 1);
        assert_eq!(insert_and_resolve(&mut store, DPNOpType::GetNonce, vec![]), 1);
        assert_eq!(insert_and_resolve(&mut store, DPNOpType::InputTarget, vec![]), 9);
        assert_eq!(resolve(&store, SymFeltRef::new_input(1, DPNBuiltInDataType::Bool)), 3);
        assert_eq!(resolve(&store, SymFeltRef::new_input(1, DPNBuiltInDataType::U32Target)), 3);
    }

    #[test]
    fn evaluates_arrays_selection_hashes_and_caches_results() {
        let mut store = SymFeltStore::new();
        let values = vec![1, 2, 3, 4].into_iter().map(SymFeltRef::new_constant).collect::<Vec<_>>();
        let split = op(&mut store, DPNOpType::SplitBits, vec![SymFeltRef::new_constant(13), SymFeltRef::new_constant(4)]);
        let selected = op(&mut store, DPNOpType::TargetAt, vec![split, SymFeltRef::new_constant(2)]);
        let sum = op(
            &mut store,
            DPNOpType::SumBits,
            vec![SymFeltRef::new_constant(1), SymFeltRef::new_constant(0), SymFeltRef::new_constant(1), SymFeltRef::new_constant(1)],
        );
        let choice = op(&mut store, DPNOpType::Select, vec![SymFeltRef::new_constant(0), SymFeltRef::new_constant(7), SymFeltRef::new_constant(8)]);
        let hash_no_pad = op(&mut store, DPNOpType::HashNoPad, values.clone());
        let hash_pad = op(&mut store, DPNOpType::HashPad, values);
        let two_to_one = op(&mut store, DPNOpType::HashTwoToOne, (1..=8).map(SymFeltRef::new_constant).collect());
        let keccak = op(&mut store, DPNOpType::Keccak256, vec![SymFeltRef::new_constant(0x01020304)]);
        let input = DummyContextEvalInput::new(vec![]);
        let mut cache = SimpleEvalCache::new();

        assert_eq!(store.resolve_array_ref_cached(split, &input, &mut cache).as_ref(), &vec![1, 0, 1, 1]);
        assert_eq!(store.resolve_felt_ref_cached(selected, &input, &mut cache), 1);
        assert_eq!(store.resolve_felt_ref_cached(selected, &input, &mut cache), 1);
        assert_eq!(store.resolve_felt_ref_cached(sum, &input, &mut cache), 3);
        assert_eq!(store.resolve_felt_ref_cached(choice, &input, &mut cache), 8);
        assert_eq!(store.resolve_array_ref_cached(hash_no_pad, &input, &mut cache).len(), 4);
        assert_eq!(store.resolve_array_ref_cached(hash_pad, &input, &mut cache).len(), 4);
        assert_eq!(store.resolve_array_ref_cached(two_to_one, &input, &mut cache).len(), 4);
        assert_eq!(store.resolve_array_ref_cached(keccak, &input, &mut cache).len(), 8);
        assert!(cache.contains_arr(split));

        let public_key_hash = op(&mut store, DPNOpType::GetUserPublicKeyHash, vec![]);
        let session_root = op(&mut store, DPNOpType::GetSessionProofTreeRoot, vec![]);
        assert_eq!(store.resolve_array_ref_cached(public_key_hash, &input, &mut cache).as_ref(), &vec![1337; 4]);
        assert_eq!(store.resolve_array_ref_cached(session_root, &input, &mut cache).as_ref(), &vec![0; 4]);
        assert_eq!(store.resolve_array_ref_cached(session_root, &input, &mut cache).as_ref(), &vec![0; 4]);
    }

    #[test]
    #[should_panic(expected = "Secp256k1Verify input length must be 36")]
    fn secp256k1_verification_rejects_an_incorrect_word_count() {
        let mut store = SymFeltStore::new();
        let verify = op(&mut store, DPNOpType::Secp256k1Verify, vec![SymFeltRef::new_constant(0); 35]);
        let _ = resolve(&store, verify);
    }

    #[test]
    fn split_bits_boundary_values_are_little_endian_and_truncated() {
        assert_eq!(split_bits(u64::MAX, 0), Vec::<u64>::new());
        assert_eq!(split_bits(0b1010, 3), vec![0, 1, 0]);
        assert_eq!(split_bits(0b1010, 6), vec![0, 1, 0, 1, 0, 0]);
    }

    #[test]
    #[should_panic(expected = "cannot sum more than 64 bits")]
    fn sum_bits_rejects_more_than_u64_bits() {
        let _ = sum_bits(&[0; 65]);
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn target_at_rejects_an_index_equal_to_array_length() {
        let mut store = SymFeltStore::new();
        let split = op(&mut store, DPNOpType::SplitBits, vec![SymFeltRef::new_constant(1), SymFeltRef::new_constant(2)]);
        let target_at = op(&mut store, DPNOpType::TargetAt, vec![split, SymFeltRef::new_constant(2)]);
        let _ = resolve(&store, target_at);
    }

    #[test]
    #[should_panic(expected = "invalid u32 value")]
    fn cast_u32_rejects_the_upper_boundary() {
        let mut store = SymFeltStore::new();
        let value = op(&mut store, DPNOpType::CastU32, vec![SymFeltRef::new_constant(0xffff_ffff)]);
        let _ = resolve(&store, value);
    }

    #[test]
    #[should_panic(expected = "a - b < 0")]
    fn u32_sub_rejects_equal_operands() {
        let mut store = SymFeltStore::new();
        let value = op(&mut store, DPNOpType::U32Sub, vec![SymFeltRef::new_constant(3), SymFeltRef::new_constant(3)]);
        let _ = resolve(&store, value);
    }

    #[test]
    #[should_panic(expected = "a + b is too large")]
    fn u32_add_rejects_overflow() {
        let mut store = SymFeltStore::new();
        let value = op(&mut store, DPNOpType::U32Add, vec![SymFeltRef::new_constant(0xffff_fffe), SymFeltRef::new_constant(2)]);
        let _ = resolve(&store, value);
    }

    #[test]
    #[should_panic(expected = "a * b is too large")]
    fn u32_mul_rejects_overflow() {
        let mut store = SymFeltStore::new();
        let value = op(&mut store, DPNOpType::U32Mul, vec![SymFeltRef::new_constant(100_000), SymFeltRef::new_constant(100_000)]);
        let _ = resolve(&store, value);
    }

    #[test]
    #[should_panic(expected = "b must be non-zero")]
    fn u32_mod_rejects_zero_divisor() {
        let mut store = SymFeltStore::new();
        let value = op(&mut store, DPNOpType::U32Mod, vec![SymFeltRef::new_constant(7), SymFeltRef::new_constant(0)]);
        let _ = resolve(&store, value);
    }

    #[test]
    #[should_panic(expected = "bool value must be 0 or 1")]
    fn cast_bool_rejects_non_boolean_values() {
        let mut store = SymFeltStore::new();
        let value = op(&mut store, DPNOpType::CastBool, vec![SymFeltRef::new_constant(2)]);
        let _ = resolve(&store, value);
    }

    #[test]
    fn unsupported_direct_evaluations_fail_with_explicit_panics() {
        let unsupported = [
            DPNOpType::SplitBits,
            DPNOpType::HashNoPad,
            DPNOpType::HashTwoToOne,
            DPNOpType::Keccak256,
            DPNOpType::HashPad,
            DPNOpType::ExpConstantPower,
            DPNOpType::ExpConstantBase,
            DPNOpType::ModConstantDividend,
            DPNOpType::ModConstantDivisor,
            DPNOpType::DivRem4,
            DPNOpType::U32AndConstant,
            DPNOpType::U32OrConstant,
            DPNOpType::U32XorConstant,
            DPNOpType::U32ShiftLeftConstantBitDistance,
            DPNOpType::U32ShiftLeftConstantValue,
            DPNOpType::U32ShiftRightConstantBitDistance,
            DPNOpType::U32ShiftRightConstantValue,
            DPNOpType::CalculateMerkleRoot,
            DPNOpType::GetUserPublicKeyHash,
            DPNOpType::GetSessionProofTreeRoot,
            DPNOpType::GetStateQueryResult,
            DPNOpType::GetStateQueryResultSingle,
            DPNOpType::GetStateCommandResultHash,
            DPNOpType::GetStateCommandResultSingle,
            DPNOpType::GetStateCommandResultArray,
        ];
        for kind in unsupported {
            let mut store = SymFeltStore::new();
            let reference = op(&mut store, kind, Vec::new());
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| resolve(&store, reference))).is_err(), "{kind}");
        }
    }
}
