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
use crate::dpn::ops::{op_types::DPNOpType, semantics, sym_felt::SymFeltRef, sym_felt_store::SymFeltStore};
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
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    semantics::felt_add(a, b)
                }
                DPNOpType::Sub => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    semantics::felt_sub(a, b)
                }
                DPNOpType::Mul => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    semantics::felt_mul(a, b)
                }
                DPNOpType::Div => {
                    let (a, b) = self.resolve_binary_felt_args_gl(felt_ref, input, cache);
                    semantics::felt_div(a.to_canonical_u64(), b.to_canonical_u64()).unwrap_or_else(|e| panic!("{e}"))
                }
                DPNOpType::BoolNot => {
                    let v = semantics::resolve_bool_value("BoolNot", self.resolve_unary_felt_arg(felt_ref, input, cache))
                        .unwrap_or_else(|e| panic!("{e}"));
                    (!v) as u64
                }
                DPNOpType::BoolAnd => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    let (a, b) = (
                        semantics::resolve_bool_value("BoolAnd", a).unwrap_or_else(|e| panic!("{e}")),
                        semantics::resolve_bool_value("BoolAnd", b).unwrap_or_else(|e| panic!("{e}")),
                    );
                    (a && b) as u64
                }
                DPNOpType::BoolOr => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    let (a, b) = (
                        semantics::resolve_bool_value("BoolOr", a).unwrap_or_else(|e| panic!("{e}")),
                        semantics::resolve_bool_value("BoolOr", b).unwrap_or_else(|e| panic!("{e}")),
                    );
                    (a || b) as u64
                }
                DPNOpType::Xor => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    semantics::bool_xor("Xor", a, b).unwrap_or_else(|e| panic!("{e}"))
                }
                DPNOpType::Nor => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    semantics::bool_nor("Nor", a, b).unwrap_or_else(|e| panic!("{e}"))
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
                DPNOpType::SumBits => {
                    // Weighted binary reconstruction sum(bit[i] * 2^i),
                    // reduced mod p — matches the witness and the circuit.
                    let values = self.resolve_array_args(felt_ref, input, cache);
                    let bits: Vec<bool> = values
                        .iter()
                        .map(|&v| semantics::resolve_bool_value("SumBits", v).unwrap_or_else(|e| panic!("{e}")))
                        .collect();
                    let sum = semantics::sum_bits_weighted(&bits).unwrap_or_else(|e| panic!("{e}"));
                    GoldilocksField::from_noncanonical_u64(sum).to_canonical_u64()
                }
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
                DPNOpType::Exp | DPNOpType::ExpConstantPower | DPNOpType::ExpConstantBase => {
                    let (base, exponent) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    semantics::felt_pow(base, exponent)
                }
                // ModConstant* carry their constant as a resolvable input
                // node, so the plain Mod logic covers them (these arms
                // previously panicked).
                DPNOpType::Mod | DPNOpType::ModConstantDividend | DPNOpType::ModConstantDivisor => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    semantics::felt_mod("Mod", a, b).unwrap_or_else(|e| panic!("{e}"))
                }
                DPNOpType::DivRem4 => panic!("you cannot directly evaluate DivRem4"),
                DPNOpType::CastU32 => {
                    let value = self.resolve_unary_felt_arg(felt_ref, input, cache);
                    semantics::cast_u32(value).unwrap_or_else(|e| panic!("{e}")) as u64
                }
                DPNOpType::U32And | DPNOpType::U32AndConstant => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    (a & b) & 0xFFFFFFFFu64
                }
                DPNOpType::U32Or | DPNOpType::U32OrConstant => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    (a | b) & 0xFFFFFFFFu64
                }
                DPNOpType::U32Xor | DPNOpType::U32XorConstant => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    (a ^ b) & 0xFFFFFFFFu64
                }
                // u32 shifts: distances >= 32 evaluate to 0 — the unguarded
                // `a << b` / `a >> b` on u64 panicked in debug and silently
                // wrapped in release for distances >= 64. The Constant*
                // variants carry their constant as a resolvable input, so
                // the same logic covers them (they previously hit todo!()).
                DPNOpType::U32ShiftLeft | DPNOpType::U32ShiftLeftConstantBitDistance | DPNOpType::U32ShiftLeftConstantValue => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    let (a, b) = (
                        semantics::u32_operand("u32 shift", a).unwrap_or_else(|e| panic!("{e}")),
                        semantics::u32_operand("u32 shift", b).unwrap_or_else(|e| panic!("{e}")),
                    );
                    semantics::u32_shl(a, b) as u64
                }
                DPNOpType::U32ShiftRight | DPNOpType::U32ShiftRightConstantBitDistance | DPNOpType::U32ShiftRightConstantValue => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    let (a, b) = (
                        semantics::u32_operand("u32 shift", a).unwrap_or_else(|e| panic!("{e}")),
                        semantics::u32_operand("u32 shift", b).unwrap_or_else(|e| panic!("{e}")),
                    );
                    semantics::u32_shr(a, b) as u64
                }
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
                DPNOpType::UnaryInverse => {
                    let value = self.resolve_unary_felt_arg_gl(felt_ref, input, cache).to_canonical_u64();
                    semantics::felt_inverse("UnaryInverse", value).unwrap_or_else(|e| panic!("{e}"))
                }
                DPNOpType::UnaryNegative => semantics::felt_neg(self.resolve_unary_felt_arg(felt_ref, input, cache)),
                DPNOpType::GetStateCommandResultHash => todo!(),
                DPNOpType::GetStateCommandResultSingle => todo!(),
                DPNOpType::GetStateCommandResultArray => todo!(),
                DPNOpType::U32InputTarget => input.get_input(felt_ref.get_input_index()),
                DPNOpType::ConstantU32 => felt_ref.get_constant_value(),
                DPNOpType::U32Add => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    semantics::u32_add("u32 add", a, b).unwrap_or_else(|e| panic!("{e}")) as u64
                }
                DPNOpType::U32Sub => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    semantics::u32_sub("u32 sub", a, b).unwrap_or_else(|e| panic!("{e}")) as u64
                }
                DPNOpType::U32Mul => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    semantics::u32_mul("u32 mul", a, b).unwrap_or_else(|e| panic!("{e}")) as u64
                }
                DPNOpType::U32Div => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    semantics::u32_div("u32 div", a, b).unwrap_or_else(|e| panic!("{e}")) as u64
                }
                DPNOpType::CastFelt => {
                    let value = self.resolve_unary_felt_arg(felt_ref, input, cache);
                    value
                }
                DPNOpType::CastBool => {
                    let value = self.resolve_unary_felt_arg(felt_ref, input, cache);
                    semantics::resolve_bool_value("CastBool", value).unwrap_or_else(|e| panic!("{e}")) as u64
                }
                DPNOpType::BoolInputTarget => input.get_input(felt_ref.get_input_index()),
                DPNOpType::U32Mod => {
                    let (a, b) = self.resolve_binary_felt_args(felt_ref, input, cache);
                    semantics::u32_mod("u32 mod", a, b).unwrap_or_else(|e| panic!("{e}")) as u64
                }
                DPNOpType::U32Exp => {
                    let (base, exponent) = self.resolve_binary_felt_args_gl(felt_ref, input, cache);
                    semantics::u32_exp("u32 exp", base.to_canonical_u64(), exponent.to_canonical_u64()).unwrap_or_else(|e| panic!("{e}")) as u64
                }
                DPNOpType::Secp256k1Verify => {
                    use k256::ecdsa::signature::hazmat::PrehashVerifier;
                    let inputs = self.resolve_array_args(felt_ref, input, cache);
                    assert!(inputs.len() == 36, "Secp256k1Verify input length must be 36");
                    // The early failures return 0 from this closure (not
                    // from the evaluator) so the result still flows into
                    // the scalar cache below.
                    (|| -> u64 {
                        let pk_u32 = inputs[0..16]
                            .to_vec()
                            .iter()
                            .map(|k| {
                                assert!(*k <= 0xffffffffu64, "secp pk.x must be [u32; 16]");
                                *k as u32
                            })
                            .collect::<Vec<u32>>();
                        let pk_x_bytes = pk_u32[0..8].iter().flat_map(|&num| num.to_le_bytes()).rev().collect::<Vec<_>>();
                        let pk_y_bytes = pk_u32[8..16].iter().flat_map(|&num| num.to_le_bytes()).rev().collect::<Vec<_>>();
                        let mut pk_sec1_bytes = vec![0x04];
                        pk_sec1_bytes.extend(pk_x_bytes);
                        pk_sec1_bytes.extend(pk_y_bytes);
                        // A malformed public key (not a curve point) or an
                        // out-of-range (r, s) fails verification — mapping them
                        // to 0 keeps parity with `verify_prehash`'s Err => 0.
                        // These previously `.expect`ed and aborted the whole
                        // evaluation on attacker-controllable inputs.
                        let vk = match k256::ecdsa::VerifyingKey::from_sec1_bytes(&pk_sec1_bytes) {
                            Ok(vk) => vk,
                            Err(_) => return 0,
                        };
                        let signature_u32 = inputs[16..32]
                            .to_vec()
                            .iter()
                            .map(|k| {
                                assert!(*k <= 0xffffffffu64, "secp signature must be [u32; 16]");
                                *k as u32
                            })
                            .collect::<Vec<u32>>();

                        let signature_r_bytes = signature_u32[0..8].iter().flat_map(|&num| num.to_le_bytes()).rev().collect::<Vec<_>>();
                        let signature_s_bytes = signature_u32[8..16].iter().flat_map(|&num| num.to_le_bytes()).rev().collect::<Vec<_>>();

                        let signature_bytes = signature_r_bytes.iter().chain(signature_s_bytes.iter()).cloned().collect::<Vec<_>>();

                        let signature = match Signature::from_slice(&signature_bytes) {
                            Ok(signature) => signature,
                            Err(_) => return 0,
                        };

                        let msg_bytes = inputs[32..36].iter().flat_map(|&num| num.to_le_bytes()).rev().collect::<Vec<_>>();

                        match vk.verify_prehash(&msg_bytes, &signature) {
                            Ok(_) => 1,
                            Err(_) => 0,
                        }
                    })()
                }
            };
            // Shared scalar subexpressions were recomputed on every use:
            // only the array cache ever inserted. Pin the scalar too.
            cache.insert(felt_ref, result);
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
                    let bits = semantics::split_bits(x, num_bits).unwrap_or_else(|e| panic!("{e}"));
                    bits.into_iter().map(|b| b as u64).collect()
                }
                DPNOpType::DivRem4 => {
                    let value = self.resolve_unary_felt_arg(felt_ref, input, cache);
                    semantics::div_rem4(value).to_vec()
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
                    semantics::keccak_u32_words_be(&data)
                        .unwrap_or_else(|e| panic!("{e}"))
                        .into_iter()
                        .map(|x| x as u64)
                        .collect()
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
