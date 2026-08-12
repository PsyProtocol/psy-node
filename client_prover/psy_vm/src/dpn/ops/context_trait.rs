use std::{
    fmt::Debug,
    ops::{
        Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign, Index, Mul, MulAssign, Neg, Not, Rem,
        RemAssign, Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
    },
};

use super::{op_types::DPNOpType, sym_felt::SymFeltRef};
use crate::dpn::QContext;
pub trait ContextFelt:
    Copy
    + Debug
    + Clone
    + PartialEq
    + Ord
    + Eq
    + Add
    + Sub
    + Mul
    + Div
    + Rem
    + BitAnd
    + BitOr
    + BitXor
    + Shl
    + Shr
    + Not
    + Neg
    + AddAssign
    + SubAssign
    + MulAssign
    + DivAssign
    + RemAssign
    + BitAndAssign
    + BitOrAssign
    + BitXorAssign
    + ShlAssign
    + ShrAssign
    + Add<u64, Output = Self>
    + Sub<u64, Output = Self>
    + Mul<u64, Output = Self>
    + Div<u64, Output = Self>
    + Rem<u64, Output = Self>
    + BitAnd<u64, Output = Self>
    + BitOr<u64, Output = Self>
    + BitXor<u64, Output = Self>
    + Shl<u64, Output = Self>
    + Shr<u64, Output = Self>
    + AddAssign<u64>
    + SubAssign<u64>
    + MulAssign<u64>
    + DivAssign<u64>
    + RemAssign<u64>
    + BitAndAssign<u64>
    + BitOrAssign<u64>
    + BitXorAssign<u64>
    + ShlAssign<u64>
    + ShrAssign<u64>
    + PartialEq<u64>
    + PartialOrd<u64>
{
    fn cns(value: u64) -> Self;
    fn cns_inverse(value: u64) -> Self;
    fn get_u64(&self) -> u64;
}
pub trait FeltSized {
    fn size() -> u64;
    fn self_size(&self) -> u64 {
        Self::size()
    }
}

impl<T: FeltSized, const N: usize> FeltSized for [T; N] {
    fn size() -> u64 {
        T::size() * N as u64
    }
}

pub trait ToFelts<F: ContextFelt>: Clone {
    fn to_felts(&self) -> Vec<F>;
    fn from_felts(felts: &[F]) -> Self;
}
pub trait QContextArray<T: ToFelts<SymFeltRef>> {
    fn q_size(&self) -> u64;
    fn q_get(&self, context: &mut QContext, index: SymFeltRef) -> T;
    fn q_get_ref(&self, context: &mut QContext, index: SymFeltRef) -> &T;
    fn q_get_mut(&mut self, context: &mut QContext, index: SymFeltRef) -> &mut T;
    fn q_set_at_index(&mut self, context: &mut QContext, index: SymFeltRef) -> T;
}
pub trait QContextArraySized<T: ToFelts<SymFeltRef>> {
    fn q_sized_size(&self) -> u64;
    fn q_get_direct(&self, index: u64) -> T;
    fn q_get_direct_ref(&self, index: u64) -> &T;
    fn q_get_direct_mut(&mut self, index: u64) -> &mut T;
    fn q_put_direct(&mut self, index: u64, value: T);
}
impl<T: ToFelts<SymFeltRef> + Clone, const N: usize> QContextArraySized<T> for [T; N] {
    default fn q_sized_size(&self) -> u64 {
        N as u64
    }

    default fn q_get_direct(&self, index: u64) -> T {
        self[index as usize].to_owned()
    }
    default fn q_get_direct_ref(&self, index: u64) -> &T {
        &self[index as usize]
    }
    default fn q_get_direct_mut(&mut self, index: u64) -> &mut T {
        self.get_mut(index as usize).unwrap()
    }
    default fn q_put_direct(&mut self, index: u64, value: T) {
        self[index as usize] = value;
    }
}
impl<T: ToFelts<SymFeltRef>, A: QContextArraySized<T>> QContextArray<T> for A {
    fn q_size(&self) -> u64 {
        self.q_sized_size()
    }

    fn q_get(&self, context: &mut QContext, index: SymFeltRef) -> T {
        if index.is_constant_type() {
            let index = index.get_constant_value();
            self.q_get_direct(index)
        } else {
            let arr_len = self.q_size();
            let index_in_of_bounds = context.op_lt(index, SymFeltRef::new_constant(arr_len));
            context.assert_true(index_in_of_bounds, "felt index out of bounds");

            let mut result = self.q_get_direct(0);

            for i in 1..self.q_size() {
                let value = self.q_get_direct(i);
                let eq = context.op_eq(index, SymFeltRef::new_constant(i));
                result = context.cselect(eq, value, result);
            }
            result
        }
    }
    fn q_get_ref(&self, _context: &mut QContext, _index: SymFeltRef) -> &T {
        todo!("q_get_ref")
    }

    fn q_get_mut(&mut self, _context: &mut QContext, _index: SymFeltRef) -> &mut T {
        todo!()
    }

    fn q_set_at_index(&mut self, _context: &mut QContext, _index: SymFeltRef) -> T {
        todo!()
    }
}

pub trait DPNContextArray<F: ContextFelt, T: ToFelts<F>, C: DPNContext<F>> {
    fn q_size(&self) -> u64;
    fn q_get(&self, context: &mut C, index: F) -> T;
    fn q_get_ref(&self, context: &mut C, index: F) -> &T;
    fn q_get_mut(&mut self, context: &mut C, index: F) -> &mut T;
    fn q_set_at_index(&mut self, context: &mut C, index: F) -> T;
}
pub trait DPNContextArraySized<F: ContextFelt, T: ToFelts<F>> {
    fn q_sized_size(&self) -> u64;
    fn q_get_direct(&self, index: u64) -> T;
    fn q_get_direct_ref(&self, index: u64) -> &T;
    fn q_get_direct_mut(&mut self, index: u64) -> &mut T;
    fn q_put_direct(&mut self, index: u64, value: T);
}
impl<F: ContextFelt, T: ToFelts<F> + Clone, const N: usize> DPNContextArraySized<F, T> for [T; N] {
    default fn q_sized_size(&self) -> u64 {
        N as u64
    }

    default fn q_get_direct(&self, index: u64) -> T {
        self[index as usize].to_owned()
    }
    default fn q_get_direct_ref(&self, index: u64) -> &T {
        &self[index as usize]
    }
    default fn q_get_direct_mut(&mut self, index: u64) -> &mut T {
        self.get_mut(index as usize).unwrap()
    }
    default fn q_put_direct(&mut self, index: u64, value: T) {
        self[index as usize] = value;
    }
}
impl<F: ContextFelt, T: ToFelts<F> + Clone> DPNContextArraySized<F, T> for Vec<T> {
    default fn q_sized_size(&self) -> u64 {
        self.len() as u64
    }

    default fn q_get_direct(&self, index: u64) -> T {
        self[index as usize].to_owned()
    }
    default fn q_get_direct_ref(&self, index: u64) -> &T {
        &self[index as usize]
    }
    default fn q_get_direct_mut(&mut self, index: u64) -> &mut T {
        self.get_mut(index as usize).unwrap()
    }
    default fn q_put_direct(&mut self, index: u64, value: T) {
        self[index as usize] = value;
    }
}

impl<F: ContextFelt, T: ToFelts<F>, C: DPNContext<F>, A: DPNContextArraySized<F, T>> DPNContextArray<F, T, C> for A {
    fn q_size(&self) -> u64 {
        self.q_sized_size()
    }

    fn q_get(&self, context: &mut C, index: F) -> T {
        let constant_types = [DPNOpType::Constant, DPNOpType::ConstantTrue, DPNOpType::ConstantFalse];
        if constant_types.contains(&context.get_op_type(index)) {
            let index = index.get_u64();
            self.q_get_direct(index)
        } else {
            let arr_len = <A as DPNContextArray<F, T, C>>::q_size(self);
            let arr_len_felt = context.op_const(arr_len);
            let index_in_of_bounds = context.op_lt(index, arr_len_felt);
            context.assert_true(index_in_of_bounds, "felt index out of bounds");

            let mut result = self.q_get_direct(0);

            for i in 1..arr_len {
                let value = self.q_get_direct(i);
                let ind = context.op_const(i);
                let eq = context.op_eq(index, ind);
                result = context.cselect(eq, value, result);
            }
            result
        }
    }
    fn q_get_ref(&self, _context: &mut C, _index: F) -> &T {
        todo!("q_get_ref")
    }

    fn q_get_mut(&mut self, _context: &mut C, _index: F) -> &mut T {
        todo!()
    }

    fn q_set_at_index(&mut self, _context: &mut C, _index: F) -> T {
        todo!()
    }
}
impl<F: ContextFelt> ToFelts<F> for F {
    fn to_felts(&self) -> Vec<F> {
        vec![*self]
    }

    fn from_felts(felts: &[F]) -> Self {
        felts[0]
    }
}

impl<T, const N: usize> Index<SymFeltRef> for [T; N] {
    type Output = T;

    fn index(&self, index: SymFeltRef) -> &Self::Output {
        if !index.is_constant_type() {
            panic!("arrays can only be indexed by constants");
        }
        &self[index.get_constant_value() as usize]
    }
}
pub trait DPNContext<F: ContextFelt>: Debug + Clone {
    fn get_constant_value(&self, a: F) -> u64;
    fn get_op_type(&self, a: F) -> DPNOpType;

    fn op_cast_u32(&mut self, a: F) -> F;
    fn op_cast_felt(&mut self, a: F) -> F;
    fn op_cast_bool(&mut self, a: F) -> F;
    fn op_select(&mut self, condition: F, a: F, b: F) -> F;
    fn op_const(&mut self, value: u64) -> F;
    fn op_const_u32(&mut self, value: u32) -> F;
    fn op_bool_not(&mut self, a: F) -> F;
    fn op_bool_and(&mut self, a: F, b: F) -> F;
    fn op_bool_or(&mut self, a: F, b: F) -> F;
    fn op_bool_or_many(&mut self, values: &[F]) -> F;
    fn op_bool_and_many(&mut self, values: &[F]) -> F;
    fn op_bool_xor(&mut self, a: F, b: F) -> F;
    fn op_add(&mut self, a: F, b: F) -> F;
    fn op_sub(&mut self, a: F, b: F) -> F;
    fn op_mul(&mut self, a: F, b: F) -> F;
    fn op_div(&mut self, a: F, b: F) -> F;
    fn op_u32_add(&mut self, a: F, b: F) -> F;
    fn op_u32_sub(&mut self, a: F, b: F) -> F;
    fn op_u32_mul(&mut self, a: F, b: F) -> F;
    fn op_u32_div(&mut self, a: F, b: F) -> F;
    fn op_mod(&mut self, a: F, b: F) -> F;
    fn op_exp(&mut self, a: F, b: F) -> F;
    fn op_u32_mod(&mut self, a: F, b: F) -> F;
    fn op_u32_exp(&mut self, a: F, b: F) -> F;
    fn op_eq(&mut self, a: F, b: F) -> F;
    fn op_neq(&mut self, a: F, b: F) -> F;
    fn op_lt(&mut self, a: F, b: F) -> F;
    fn op_lte(&mut self, a: F, b: F) -> F;
    fn op_gt(&mut self, a: F, b: F) -> F;
    fn op_gte(&mut self, a: F, b: F) -> F;
    fn op_neg(&mut self, a: F) -> F;

    // start u32 ops
    fn op_u32_xor(&mut self, a: F, b: F) -> F;
    fn op_u32_or(&mut self, a: F, b: F) -> F;
    fn op_u32_and(&mut self, a: F, b: F) -> F;
    fn op_u32_shl(&mut self, a: F, b: F) -> F;
    fn op_u32_shr(&mut self, a: F, b: F) -> F;

    // end u32 ops
    fn op_true(&mut self) -> F;

    fn op_false(&mut self) -> F;

    // secp256k1 sign
    fn op_secp256k1_verify(&mut self, public_key: [F; 16], msg_hash: [F; 4], signature: [F; 16]) -> F;

    fn add_input(&mut self) -> F;
    fn add_u32_input(&mut self) -> F;
    fn add_bool_input(&mut self) -> F;
    fn add_inputs(&mut self, count: u64) -> Vec<F>;
    fn assert_eq(&mut self, left: F, right: F, message: &'static str);
    fn assert_true(&mut self, left: F, message: &'static str);
    fn cset<V: ToFelts<F>>(&mut self, old_value: V, new_value: V) -> V;
    fn cset_state_at<V: ToFelts<F>>(&mut self, sub_index: F, new_value: V) -> V;
    fn cset_state_hash_at(&mut self, slot_index: F, new_value: [F; 4]) -> [F; 4];
    fn cset_state_range_at(&mut self, sub_slot_index: F, values: &[F]);

    fn cinvoke_external_contract_function_sync(&mut self, contract_id: F, method_id: F, input_args: Vec<F>, num_outputs: u32) -> Vec<F>;
    fn cinvoke_external_contract_function_deferred(&mut self, contract_id: F, method_id: F, input_args: Vec<F>) -> [F; 4];
    fn get_state_hash_at(&mut self, slot_index: F) -> [F; 4];
    fn get_state_range_at(&mut self, sub_slot_index: F, length: F) -> Vec<F>;
    fn get_other_contract_state_hash_at(&mut self, contract_state_tree_height: F, contract_id: F, slot_index: F) -> [F; 4];
    fn get_other_user_contract_state_hash_at(&mut self, contract_state_tree_height: F, user_id: F, contract_id: F, slot_index: F) -> [F; 4];
    fn get_other_user_contract_state_range_at(
        &mut self,
        contract_state_tree_height: F,
        user_id: F,
        contract_id: F,
        sub_slot_index: F,
        length: F,
    ) -> Vec<F>;

    fn cset_state<V: ToFelts<F>>(&mut self, old_value: V, new_value: V) -> V;
    fn start_if_block(&mut self, condition: F);
    fn start_else_if_block(&mut self, condition: F);
    fn start_else_block(&mut self);
    fn end_if_block(&mut self);
    fn resolve_current_condition(&mut self) -> F;
    fn get_current_condition(&self) -> F;

    // std lib
    fn hash(&mut self, values: &[F]) -> [F; 4];
    fn hash_two_to_one(&mut self, left: &[F; 4], right: &[F; 4]) -> [F; 4];
    fn keccak256(&mut self, values: &[F]) -> [F; 8];
    fn split_bits(&mut self, value: F, num_bits: u64) -> Vec<F>;
    fn sum_bits(&mut self, bits: &[F]) -> F;

    fn get_user_id(&mut self) -> F;
    fn get_contract_id(&mut self) -> F;
    fn get_contract_deployer(&mut self, contract_id: F) -> [F; 4];
    fn get_contract_state_tree_height(&mut self, contract_id: F) -> F;
    fn get_caller_contract_id(&mut self) -> F;
    fn get_checkpoint_id(&mut self) -> F;
    fn get_last_nonce(&mut self) -> F;
    fn get_user_public_key_hash(&mut self) -> [F; 4];
    fn get_session_proof_tree_root(&mut self) -> [F; 4];

    // Checkpoint stats helper functions
    fn get_checkpoint_stats(&mut self, checkpoint_id: F) -> Vec<F>;
    fn get_register_users_root(&mut self, checkpoint_id: F) -> [F; 4];
    fn get_gutas_root(&mut self, checkpoint_id: F) -> [F; 4];
    fn get_deploy_contracts_root(&mut self, checkpoint_id: F) -> [F; 4];

    // New checkpoint stats intrinsics
    fn get_guta_fees_collected(&mut self, checkpoint_id: F) -> F;
    fn get_da_fees_collected(&mut self, checkpoint_id: F) -> F;
    fn get_user_ops_processed(&mut self, checkpoint_id: F) -> F;
    fn get_total_transactions(&mut self, checkpoint_id: F) -> F;
    fn get_slots_modified(&mut self, checkpoint_id: F) -> F;
    fn get_register_users_completed(&mut self, checkpoint_id: F) -> F;
    fn get_gutas_completed(&mut self, checkpoint_id: F) -> F;
    fn get_deploy_contracts_completed(&mut self, checkpoint_id: F) -> F;

    // Global state roots helper functions
    fn get_global_state_roots(&mut self, checkpoint_id: F) -> Vec<F>;
    fn get_checkpoint_user_tree_root(&mut self, checkpoint_id: F) -> [F; 4];
    fn get_checkpoint_contract_tree_root(&mut self, checkpoint_id: F) -> [F; 4];
    fn get_checkpoint_deposit_tree_root(&mut self, checkpoint_id: F) -> [F; 4];
    fn get_checkpoint_withdrawal_tree_root(&mut self, checkpoint_id: F) -> [F; 4];
    fn get_checkpoint_user_registration_tree_root(&mut self, checkpoint_id: F) -> [F; 4];

    // state operations
    fn op_get_state_felt(&mut self, contract_state_tree_height: F, contract_id: F, user_id: F, index: F) -> F;
    fn op_set_state_felt(&mut self, index: F, value: F) -> F;
    fn op_set_state_obj<T: ToFelts<F>>(&mut self, index: F, value: T) -> T;
    fn clear_entire_tree(&mut self) -> Vec<F>;
    fn cselect<V: ToFelts<F>>(&mut self, condition: F, if_true: V, if_false: V) -> V {
        let if_true = if_true.to_felts();
        let if_false = if_false.to_felts();
        let mut result = vec![];
        for i in 0..if_true.len() {
            result.push(self.op_select(condition, if_true[i], if_false[i]));
        }
        ToFelts::from_felts(&result)
    }

    // IMT (Indexed Merkle Tree) state operations
    fn imt_get_value(&mut self, key: [F; 4], base_offset: F, capacity: F) -> [F; 4];
    fn imt_get_other_user_value(
        &mut self,
        contract_state_tree_height: F,
        user_id: F,
        contract_id: F,
        key: [F; 4],
        base_offset: F,
        capacity: F,
    ) -> [F; 4];
    fn imt_contains_other_user(&mut self, contract_state_tree_height: F, user_id: F, contract_id: F, key: [F; 4], base_offset: F, capacity: F) -> F;
    fn imt_insert(&mut self, key: [F; 4], value: [F; 4], base_offset: F, capacity: F) -> [F; 4];
    fn imt_update(&mut self, key: [F; 4], new_value: [F; 4], base_offset: F, capacity: F) -> [F; 4];
    fn imt_contains(&mut self, key: [F; 4], base_offset: F, capacity: F) -> F;

    // event operations
    fn emit_event(&mut self, event_data: Vec<F>);
}
