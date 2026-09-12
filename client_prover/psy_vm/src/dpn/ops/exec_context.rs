use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::traits::to_qfelts::QFeltSized;
use psy_client_data::qdata::checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeafStats};

use super::{
    context_trait::{DPNContext, ToFelts},
    op_types::{DPNBuiltInDataType, DPNOpType},
    state_cmd::{
        data::{
            DPNStateCmd, DPNStateCmdClearEntireTree, DPNStateCmdGetCheckpointLeafStats, DPNStateCmdGetContractLeaf, DPNStateCmdGetGlobalStateRoots,
            DPNStateCmdGetOtherUserContractStateSlotHash, DPNStateCmdGetOtherUserContractStateSlotRange,
            DPNStateCmdGetOtherUserContractStateSlotSingle, DPNStateCmdGetSelfUserCurrentContractStateSlotHash,
            DPNStateCmdGetSelfUserExternalContractStateSlotHash, DPNStateCmdInvokeExternalContractFunctionDeferred,
            DPNStateCmdInvokeExternalContractFunctionSync, DPNStateCmdSetContractStateSlotHash, DPNStateCmdSetContractStateSlotRange,
            DPNStateCmdSetContractStateSlotSingle,
        },
        store::DPNStateCommandStore,
        types::DPNStateCmdCore,
    },
    sym_felt::{SymFeltRef, SymRefAssertion},
    sym_felt_store::SymFeltStore,
};
use crate::dpn::ops::{context_trait::ContextFelt, sym_felt::SymFeltRefValue};

#[derive(Debug, Clone)]
pub struct EventRecord<F: ContextFelt> {
    pub condition: F,
    pub checkpoint_id: F,
    pub user_id: F,
    pub contract_id: F,
    pub data: Vec<F>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::Field64;

    #[test]
    fn builds_scalar_expression_graphs_and_constant_folds_all_basic_operator_families() {
        let mut ctx = QExecContext::new();
        let target = ctx.add_input();
        let u32_value = ctx.add_u32_input();
        let boolean = ctx.add_bool_input();
        let one = ctx.op_const(1);
        let two = ctx.op_const(2);
        let u32_one = ctx.op_const_u32(1);
        let u32_two = ctx.op_const_u32(2);

        assert_eq!(ctx.op_add(one, two).get_constant_value(), 3);
        assert_eq!(ctx.op_sub(two, one).get_constant_value(), 1);
        assert_eq!(ctx.op_mul(two, two).get_constant_value(), 4);
        assert_eq!(ctx.op_div(two, two).get_constant_value(), 1);
        assert_eq!(ctx.op_mod(two, two).get_constant_value(), 0);
        assert_eq!(ctx.op_exp(two, u32_two).get_op_type(), DPNOpType::ExpConstantPower);
        assert_eq!(ctx.op_bool_not(SymFeltRef::constant_false()).get_constant_value(), 1);
        assert_eq!(ctx.op_bool_and(SymFeltRef::constant_true(), SymFeltRef::constant_true()).get_constant_value(), 1);
        assert_eq!(ctx.op_bool_or(SymFeltRef::constant_false(), SymFeltRef::constant_true()).get_constant_value(), 1);
        assert_eq!(ctx.op_bool_xor(one, two).get_constant_value(), 3);
        assert_eq!(ctx.op_eq(one, one).get_constant_value(), 1);
        assert_eq!(ctx.op_neq(one, two).get_constant_value(), 1);
        assert_eq!(ctx.op_lt(one, two).get_constant_value(), 1);
        assert_eq!(ctx.op_lte(one, two).get_constant_value(), 1);
        assert_eq!(ctx.op_gt(two, one).get_constant_value(), 1);
        assert_eq!(ctx.op_gte(two, one).get_constant_value(), 1);
        assert_eq!(ctx.op_u32_add(u32_one, u32_two).get_constant_value(), 3);
        assert_eq!(ctx.op_u32_sub(u32_two, u32_one).get_constant_value(), 1);
        assert_eq!(ctx.op_u32_mul(u32_two, u32_two).get_constant_value(), 4);
        assert_eq!(ctx.op_u32_div(u32_two, u32_two).get_constant_value(), 1);
        assert_eq!(ctx.op_u32_mod(u32_two, u32_two).get_constant_value(), 0);
        assert_eq!(ctx.op_u32_exp(u32_two, u32_two).get_constant_value(), 4);
        assert_eq!(ctx.op_u32_and(u32_one, u32_two).get_constant_value(), 0);
        assert_eq!(ctx.op_u32_or(u32_one, u32_two).get_constant_value(), 3);
        assert_eq!(ctx.op_u32_xor(u32_one, u32_two).get_constant_value(), 3);
        assert_eq!(ctx.op_u32_shl(u32_one, u32_one).get_constant_value(), 2);
        assert_eq!(ctx.op_u32_shr(u32_two, u32_one).get_constant_value(), 1);
        assert_eq!(ctx.op_select(SymFeltRef::constant_true(), one, two), one);
        assert_eq!(ctx.op_select(SymFeltRef::constant_false(), one, two), two);
        assert_eq!(ctx.op_cast_u32(one).get_op_type(), DPNOpType::ConstantU32);
        assert_eq!(ctx.op_cast_felt(u32_one).get_op_type(), DPNOpType::Constant);
        assert_eq!(ctx.op_cast_bool(one).get_op_type(), DPNOpType::ConstantTrue);
        assert_eq!(ctx.op_bool_or_many(&[boolean, SymFeltRef::constant_false()]).get_op_type(), DPNOpType::BoolOr);
        assert_eq!(ctx.op_bool_and_many(&[boolean, SymFeltRef::constant_true()]).get_op_type(), DPNOpType::BoolAnd);
        assert_eq!(ctx.op_add(target, one).get_op_type(), DPNOpType::Add);
        assert_eq!(ctx.op_u32_add(u32_value, u32_one).get_op_type(), DPNOpType::U32Add);
        assert_eq!(ctx.input_count, 3);
    }

    #[test]
    fn builds_state_control_flow_hash_checkpoint_and_imt_graphs() {
        let mut ctx = QExecContext::new_with_contract_state_tree_height(8);
        let zero = ctx.op_const(0);
        let one = ctx.op_const(1);
        let two = ctx.op_const(2);
        let key = [one, two, zero, one];
        let value = [two, one, two, one];

        let true_value = ctx.op_true();
        ctx.assert_true(true_value, "true assertion");
        let first_condition = ctx.op_eq(one, one);
        ctx.start_if_block(first_condition);
        ctx.cset_state_at(zero, two);
        ctx.emit_event(vec![one, two]);
        let second_condition = ctx.op_eq(one, two);
        ctx.start_else_if_block(second_condition);
        ctx.cset_state_range_at(one, &[one, two]);
        ctx.start_else_block();
        ctx.cset_state_hash_at(one, value);
        ctx.end_if_block();
        assert_eq!(ctx.get_current_condition(), SymFeltRef::constant_true());

        let current_hash = ctx.get_state_hash_at(zero);
        assert_eq!(current_hash.len(), 4);
        assert_eq!(ctx.get_state_range_at(one, two).len(), 2);
        assert_eq!(ctx.get_other_contract_state_hash_at(two, two, zero).len(), 4);
        assert_eq!(ctx.get_other_user_contract_state_hash_at(two, one, two, zero).len(), 4);
        assert_eq!(ctx.get_other_user_contract_state_range_at(two, one, two, zero, two).len(), 2);

        assert_eq!(ctx.hash(&[one, two]).len(), 4);
        assert_eq!(ctx.hash_two_to_one(&key, &value).len(), 4);
        assert_eq!(ctx.keccak256(&[one, two]).len(), 8);
        let bits = ctx.split_bits(one, 4);
        assert_eq!(bits.len(), 4);
        assert_eq!(ctx.sum_bits(&bits).get_op_type(), DPNOpType::SumBits);

        assert_eq!(ctx.get_contract_deployer(one).len(), 4);
        ctx.get_contract_state_tree_height(one);
        ctx.get_user_public_key_hash();
        ctx.get_session_proof_tree_root();
        ctx.get_checkpoint_stats(one);
        ctx.get_register_users_root(one);
        ctx.get_gutas_root(one);
        ctx.get_deploy_contracts_root(one);
        ctx.get_guta_fees_collected(one);
        ctx.get_da_fees_collected(one);
        ctx.get_user_ops_processed(one);
        ctx.get_total_transactions(one);
        ctx.get_slots_modified(one);
        ctx.get_register_users_completed(one);
        ctx.get_gutas_completed(one);
        ctx.get_deploy_contracts_completed(one);
        ctx.get_global_state_roots(one);
        ctx.get_checkpoint_user_tree_root(one);
        ctx.get_checkpoint_contract_tree_root(one);
        ctx.get_checkpoint_deposit_tree_root(one);
        ctx.get_checkpoint_withdrawal_tree_root(one);
        ctx.get_checkpoint_user_registration_tree_root(one);

        assert_eq!(ctx.imt_get_value(key, zero, two).len(), 4);
        assert_eq!(ctx.imt_get_other_user_value(two, one, two, key, zero, two).len(), 4);
        ctx.imt_contains_other_user(two, one, two, key, zero, two);
        assert_eq!(ctx.imt_insert(key, value, zero, two).len(), 4);
        assert_eq!(ctx.imt_update(key, value, zero, two).len(), 4);
        ctx.imt_contains(key, zero, two);
        ctx.clear_entire_tree();
        ctx.cinvoke_external_contract_function_sync(two, one, vec![one, two], 2);
        ctx.cinvoke_external_contract_function_deferred(two, one, vec![one, two]);

        assert!(!ctx.state_cmd_store.commands.is_empty());
        assert!(!ctx.events.is_empty());
    }

    #[test]
    fn simplification_cast_shift_and_conditional_boundaries_cover_nonconstant_paths() {
        let mut ctx = QExecContext::new();
        ctx.finalize();
        let target = ctx.add_input();
        let other = ctx.add_input();
        let u32_input = ctx.add_u32_input();
        let bool_input = ctx.add_bool_input();
        assert_eq!(ctx.add_inputs(0), Vec::<SymFeltRef>::new());
        assert_eq!(ctx.add_inputs(2).len(), 2);
        let seven = ctx.op_const(7);
        assert_eq!(ctx.get_constant_value(seven), 7);
        assert_eq!(ctx.get_op_type(target), DPNOpType::InputTarget);

        let zero = ctx.op_const(0);
        let one = ctx.op_const(1);
        let two = ctx.op_const(2);
        let above_u32 = ctx.op_const(u32::MAX as u64 + 1);
        let u32_one = ctx.op_const_u32(1);
        assert_eq!(ctx.op_add(target, zero), target);
        assert_eq!(ctx.op_sub(target, zero), target);
        assert_eq!(ctx.op_mul(target, zero), target);
        assert_eq!(ctx.op_select(bool_input, target, target), target);
        assert_eq!(ctx.op_select(zero, target, other), other);
        assert_eq!(ctx.op_select(two, target, other), target);
        assert_eq!(ctx.op_cast_u32(u32_input), u32_input);
        assert_eq!(ctx.op_cast_felt(target), target);
        assert_eq!(ctx.op_cast_bool(bool_input), bool_input);
        assert_eq!(ctx.op_cast_bool(zero), SymFeltRef::constant_false());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ctx.op_cast_bool(two))).is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ctx.op_cast_u32(above_u32))).is_err());

        assert_eq!(ctx.op_bool_and(u32_one, u32_one).get_constant_value(), 1);
        assert_eq!(ctx.op_bool_or(u32_one, u32_one).get_constant_value(), 1);
        assert_eq!(ctx.op_bool_xor(u32_one, u32_one).get_constant_value(), 0);
        assert_eq!(ctx.op_add(u32_one, u32_one).get_constant_value(), 2);
        assert_eq!(ctx.op_sub(u32_one, u32_one).get_constant_value(), 0);
        assert_eq!(ctx.op_mul(u32_one, u32_one).get_constant_value(), 1);
        assert_eq!(ctx.op_div(u32_one, u32_one).get_constant_value(), 1);
        assert_eq!(ctx.op_eq(u32_one, u32_one).get_constant_value(), 1);
        assert_eq!(ctx.op_neq(u32_one, u32_one).get_constant_value(), 0);
        assert_eq!(ctx.op_lt(u32_one, u32_one).get_constant_value(), 0);
        assert_eq!(ctx.op_lte(u32_one, u32_one).get_constant_value(), 1);
        assert_eq!(ctx.op_gt(u32_one, u32_one).get_constant_value(), 0);
        assert_eq!(ctx.op_gte(u32_one, u32_one).get_constant_value(), 1);
        assert_eq!(ctx.op_neg(one).get_constant_value(), GoldilocksField::ORDER - 1);

        assert_eq!(ctx.op_exp(u32_one, target).get_op_type(), DPNOpType::ExpConstantBase);
        assert_eq!(ctx.op_exp(target, u32_one).get_op_type(), DPNOpType::ExpConstantPower);
        assert_eq!(ctx.op_u32_shl(u32_one, u32_input).get_op_type(), DPNOpType::U32ShiftLeftConstantValue);
        assert_eq!(ctx.op_u32_shl(u32_input, u32_one).get_op_type(), DPNOpType::U32ShiftLeftConstantBitDistance);
        assert_eq!(ctx.op_u32_shl(u32_input, target).get_op_type(), DPNOpType::U32ShiftLeft);
        assert_eq!(ctx.op_u32_shr(u32_one, u32_input).get_op_type(), DPNOpType::U32ShiftRightConstantValue);
        assert_eq!(ctx.op_u32_shr(u32_input, u32_one).get_op_type(), DPNOpType::U32ShiftRightConstantBitDistance);
        assert_eq!(ctx.op_u32_shr(u32_input, target).get_op_type(), DPNOpType::U32ShiftRight);

        let before = ctx.assertions.len();
        ctx.start_if_block(SymFeltRef::constant_false());
        ctx.assert_eq(target, other, "skipped");
        assert_eq!(ctx.cset(target, other), target);
        ctx.end_if_block();
        assert_eq!(ctx.assertions.len(), before);
        ctx.start_if_block(bool_input);
        ctx.assert_eq(target, other, "conditional");
        assert_eq!(ctx.cset(target, other).get_op_type(), DPNOpType::Select);
        ctx.end_if_block();
        assert_eq!(ctx.assertions.len(), before + 1);
    }

    #[test]
    fn state_reference_error_and_side_effect_boundaries_are_explicit() {
        let mut ctx = QExecContext::new();
        let zero = ctx.op_const(0);
        let one = ctx.op_const(1);
        let current_contract = ctx.get_contract_id();
        let current_user = ctx.get_user_id();
        assert_eq!(ctx.create_contract_state_ref(32, current_contract, current_user, SymFeltRef::constant_true(), zero, vec![one]).get_op_type(), DPNOpType::GetStateCommandResultArray);
        assert_eq!(ctx.create_contract_state_ref(32, current_contract, current_user, SymFeltRef::constant_true(), zero, vec![one, zero]).get_op_type(), DPNOpType::GetStateCommandResultArray);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ctx.create_contract_state_ref(32, one, current_user, SymFeltRef::constant_true(), zero, vec![one])
        }))
        .is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ctx.create_contract_state_ref(32, current_contract, one, SymFeltRef::constant_true(), zero, vec![one])
        }))
        .is_err());
        let before = ctx.state_cmd_store.commands.len();
        ctx.resolve_state_cmd_side_effect(DPNStateCmd::ClearEntireTree(DPNStateCmdClearEntireTree { condition: SymFeltRef::constant_true() }));
        assert_eq!(ctx.state_cmd_store.commands.len(), before + 1);
    }

    #[test]
    fn state_get_reference_covers_every_owner_scope_and_length_boundary() {
        let mut ctx = QExecContext::new();
        let height = ctx.op_const(32);
        let slot = ctx.op_const(9);
        let current_contract = ctx.get_contract_id();
        let current_user = ctx.get_user_id();
        let external_contract = ctx.op_const(17);
        let other_user = ctx.op_const(23);

        let cases = [
            (current_contract, current_user, 1, DPNOpType::GetStateCommandResultSingle),
            (current_contract, current_user, 0, DPNOpType::GetStateCommandResultArray),
            (external_contract, current_user, 1, DPNOpType::GetStateCommandResultSingle),
            (external_contract, current_user, 2, DPNOpType::GetStateCommandResultArray),
            (current_contract, other_user, 1, DPNOpType::GetStateCommandResultSingle),
            (external_contract, other_user, u32::MAX, DPNOpType::GetStateCommandResultArray),
        ];
        for (contract, user, length, expected) in cases {
            assert_eq!(ctx.create_contract_state_get_ref(height, contract, user, slot, length).get_op_type(), expected);
        }
        assert_eq!(ctx.state_cmd_store.commands.len(), cases.len());
    }

    #[test]
    fn add_simplification_handles_nested_constants_on_both_sides() {
        let mut ctx = QExecContext::new();
        let input = ctx.add_input();
        let zero = ctx.op_const(0);
        let two = ctx.op_const(2);
        let three = ctx.op_const(3);

        assert_eq!(ctx.simplify_add(zero, input), input);
        assert_eq!(ctx.simplify_add(input, zero), input);

        let constant_first = ctx.op_add(two, input);
        let folded_first = ctx.simplify_add(three, constant_first);
        assert_eq!(folded_first.get_op_type(), DPNOpType::Add);
        assert_eq!(ctx.store.get_direct_children(folded_first)[0].get_constant_value(), 5);

        let constant_second = ctx.op_add(input, two);
        let folded_second = ctx.simplify_add(three, constant_second);
        assert_eq!(ctx.store.get_direct_children(folded_second)[0].get_constant_value(), 5);

        let reversed = ctx.simplify_add(constant_second, three);
        assert_eq!(ctx.store.get_direct_children(reversed)[0].get_constant_value(), 5);
        let other_input = ctx.add_input();
        assert_eq!(ctx.simplify_add(input, other_input).get_op_type(), DPNOpType::Add);
    }

    #[test]
    fn control_flow_cast_identity_and_protocol_value_boundaries_are_explicit() {
        let mut ctx = QExecContext::new_with_contract_state_tree_height(19);
        let target = ctx.add_input();
        let u32_input = ctx.add_u32_input();
        let bool_input = ctx.add_bool_input();
        let zero = ctx.op_const(0);
        let one = ctx.op_const(1);

        assert_eq!(ctx.op_cast_u32(target).get_op_type(), DPNOpType::CastU32);
        assert_eq!(ctx.op_cast_felt(u32_input).get_op_type(), DPNOpType::CastFelt);
        assert_eq!(ctx.op_cast_bool(target).get_op_type(), DPNOpType::CastBool);
        assert_eq!(ctx.op_neg(target).get_op_type(), DPNOpType::UnaryNegative);
        assert_eq!(ctx.op_exp(target, target).get_op_type(), DPNOpType::Exp);
        assert_eq!(ctx.op_false(), SymFeltRef::constant_false());
        assert_eq!(ctx.cset(zero, one), one);

        assert_eq!(ctx.get_caller_contract_id().get_op_type(), DPNOpType::GetCallerContractId);
        assert_eq!(ctx.get_checkpoint_id().get_op_type(), DPNOpType::GetCheckpointId);
        assert_eq!(ctx.get_last_nonce().get_op_type(), DPNOpType::GetNonce);
        assert_eq!(ctx.op_secp256k1_verify([target; 16], [one; 4], [zero; 16]).get_op_type(), DPNOpType::Secp256k1Verify);

        for action in [0, 1, 2] {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match action {
                0 => ctx.start_else_if_block(bool_input),
                1 => ctx.start_else_block(),
                _ => ctx.end_if_block(),
            }));
            assert!(result.is_err());
        }

        ctx.start_if_block(SymFeltRef::constant_true());
        assert_eq!(ctx.get_current_condition(), SymFeltRef::constant_true());
        let assertions = ctx.assertions.len();
        ctx.assert_eq(zero, one, "true branch");
        assert_eq!(ctx.assertions.len(), assertions + 1);
        assert_eq!(ctx.cset(zero, one), one);
        ctx.end_if_block();

        ctx.start_if_block(SymFeltRef::constant_false());
        assert_eq!(ctx.get_current_condition(), SymFeltRef::constant_false());
        let events = ctx.events.len();
        ctx.emit_event(vec![one]);
        assert_eq!(ctx.events.len(), events);
        ctx.end_if_block();

        let current_contract = ctx.get_contract_id();
        let other_user = ctx.op_const(41);
        let key = [zero, one, zero, one];
        assert_eq!(ctx.get_other_contract_state_hash_at(one, current_contract, zero).len(), 4);
        assert_eq!(ctx.get_other_user_contract_state_hash_at(one, other_user, current_contract, zero).len(), 4);
        assert_eq!(ctx.get_other_user_contract_state_range_at(one, other_user, current_contract, zero, zero), Vec::<SymFeltRef>::new());
        assert_eq!(ctx.imt_get_other_user_value(one, other_user, current_contract, key, zero, one).len(), 4);
        assert_eq!(ctx.imt_contains_other_user(one, other_user, current_contract, key, zero, one).get_op_type(), DPNOpType::TargetAt);

        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ctx.get_state_range_at(zero, target))).is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ctx.get_other_user_contract_state_range_at(one, other_user, current_contract, zero, target)
        }))
        .is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ctx.cset_state(target, one))).is_err());
    }
}

#[derive(Debug, Clone)]
pub struct IfConditionStack {
    pub conditions: Vec<SymFeltRef>,
    pub current_condition: SymFeltRef,
}

#[derive(Debug, Clone)]
pub struct QExecContext {
    pub state_cmd_store: DPNStateCommandStore,
    pub store: SymFeltStore,
    pub input_count: u64,
    pub input_types: Vec<DPNBuiltInDataType>,
    pub assertions: Vec<SymRefAssertion>,
    condition_stack: Vec<IfConditionStack>,
    current_condition: SymFeltRef,
    #[allow(dead_code)]
    external_function_call_count: u16,
    contract_state_tree_height: u16,
    pub set_state_command_count: u32,

    pub events: Vec<EventRecord<SymFeltRef>>,
}

impl QExecContext {
    pub fn new() -> Self {
        Self::new_with_contract_state_tree_height(32)
    }

    pub fn new_with_contract_state_tree_height(contract_state_tree_height: u16) -> Self {
        QExecContext {
            state_cmd_store: DPNStateCommandStore::new(),
            store: SymFeltStore::new(),
            input_count: 0,
            input_types: vec![],
            assertions: vec![],
            condition_stack: vec![],
            current_condition: SymFeltRef::new_valueless(DPNOpType::ConstantTrue),
            external_function_call_count: 0,
            contract_state_tree_height,
            set_state_command_count: 0,
            events: vec![],
        }
    }

    pub fn finalize(&mut self) {}

    fn resolve_state_cmd_base(&mut self, cmd: DPNStateCmd<SymFeltRef>) -> SymFeltRef {
        let op_type = match cmd.get_hint_result_type() {
            DPNBuiltInDataType::Target => DPNOpType::GetStateCommandResultSingle,
            DPNBuiltInDataType::HashOut => DPNOpType::GetStateCommandResultHash,
            DPNBuiltInDataType::TargetArray => DPNOpType::GetStateCommandResultArray,
            _ => panic!("unsupported hint result type {}", cmd.get_hint_result_type()),
        };
        let result = self.state_cmd_store.injest_command(cmd);
        let value = SymFeltRefValue {
            op_type,
            const_param: result as u64,
            inputs: vec![],
        };
        self.store.insert(value)
    }

    fn resolve_state_cmd_side_effect(&mut self, cmd: DPNStateCmd<SymFeltRef>) {
        self.state_cmd_store.injest_command(cmd);
    }

    fn create_self_user_current_contract_state_ref(
        &mut self,
        condition: SymFeltRef,
        sub_slot_index: SymFeltRef,
        values: Vec<SymFeltRef>,
    ) -> SymFeltRef {
        if values.len() == 1 {
            self.resolve_state_cmd_base(DPNStateCmd::SetContractStateSlotSingle(DPNStateCmdSetContractStateSlotSingle {
                condition,
                sub_slot_index,
                value: values[0],
            }))
        } else {
            self.resolve_state_cmd_base(DPNStateCmd::SetContractStateSlotRange(DPNStateCmdSetContractStateSlotRange {
                sub_slot_index,
                value: values,
                condition,
            }))
        }
    }

    fn create_contract_state_ref(
        &mut self,
        _contract_state_tree_height: u16,
        contract_id: SymFeltRef,
        user_id: SymFeltRef,
        condition: SymFeltRef,
        sub_slot_index: SymFeltRef,
        values: Vec<SymFeltRef>,
    ) -> SymFeltRef {
        let is_same_contract = contract_id.get_op_type().eq(&DPNOpType::GetContractId);
        let is_same_user = user_id.get_op_type().eq(&DPNOpType::GetUserId);
        if is_same_contract && is_same_user {
            self.create_self_user_current_contract_state_ref(condition, sub_slot_index, values)
        } else if is_same_user {
            unimplemented!()
        } else {
            panic!("Cannot modify contract state of other user");
        }
    }

    fn create_contract_state_get_ref(
        &mut self,
        contract_state_tree_height: SymFeltRef,
        contract_id: SymFeltRef,
        user_id: SymFeltRef,
        sub_slot_index: SymFeltRef,
        length: u32,
    ) -> SymFeltRef {
        let is_same_contract = contract_id.get_op_type().eq(&DPNOpType::GetContractId);
        let is_same_user = user_id.get_op_type().eq(&DPNOpType::GetUserId);
        if is_same_contract && is_same_user {
            if length == 1 {
                self.resolve_state_cmd_base(DPNStateCmd::get_self_user_current_contract_state_slot_single(sub_slot_index))
            } else {
                self.resolve_state_cmd_base(DPNStateCmd::get_self_user_current_contract_state_slot_range(sub_slot_index, length))
            }
        } else if is_same_user {
            if length == 1 {
                self.resolve_state_cmd_base(DPNStateCmd::get_self_user_external_contract_state_slot_single(
                    contract_id,
                    contract_state_tree_height,
                    sub_slot_index,
                ))
            } else {
                self.resolve_state_cmd_base(DPNStateCmd::get_self_user_external_contract_state_slot_range(
                    contract_id,
                    contract_state_tree_height,
                    sub_slot_index,
                    length,
                ))
            }
        } else {
            if length == 1 {
                self.resolve_state_cmd_base(DPNStateCmd::GetOtherUserContractStateSlotSingle(
                    DPNStateCmdGetOtherUserContractStateSlotSingle {
                        contract_id,
                        sub_slot_index,
                        contract_state_tree_height,
                        user_id,
                    },
                ))
            } else {
                self.resolve_state_cmd_base(DPNStateCmd::GetOtherUserContractStateSlotRange(
                    DPNStateCmdGetOtherUserContractStateSlotRange {
                        contract_id,
                        sub_slot_index,
                        contract_state_tree_height,
                        user_id,
                        length,
                    },
                ))
            }
        }
    }

    #[allow(dead_code)]
    fn simplify_add(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        let a_type = a.get_op_type();
        let b_type = b.get_op_type();
        if a_type == DPNOpType::Constant && b_type == DPNOpType::Add {
            let b_inner = self.store.get_direct_children(b);
            if b_inner.len() == 2 {
                let b_a = b_inner[0];
                let b_b = b_inner[1];
                if b_a.get_op_type() == DPNOpType::Constant {
                    let v = self.op_add(a, b_a);
                    return self.op_add(v, b_b);
                } else if b_b.get_op_type() == DPNOpType::Constant {
                    let v = self.op_add(a, b_b);
                    return self.op_add(v, b_a);
                }
            }
        } else if b_type == DPNOpType::Constant && a_type == DPNOpType::Add {
            return self.simplify_add(b, a);
        }
        if a_type == DPNOpType::Constant && a.get_constant_value() == 0 {
            return b;
        }
        if b_type == DPNOpType::Constant && b.get_constant_value() == 0 {
            return a;
        }
        let value = SymFeltRefValue {
            op_type: DPNOpType::Add,
            const_param: 0,
            inputs: vec![a, b],
        };
        self.store.insert(value)
    }

    fn op_std_binary_op(&mut self, op_type: DPNOpType, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        let a_type = a.get_op_type();
        let b_type = b.get_op_type();
        if (a_type == DPNOpType::Constant || a_type == DPNOpType::ConstantTrue || a_type == DPNOpType::ConstantFalse)
            && (b_type == DPNOpType::Constant || b_type == DPNOpType::ConstantTrue || b_type == DPNOpType::ConstantFalse)
        {
            let a_val = a.get_constant_value();
            let b_val = b.get_constant_value();
            return self.op_const(op_type.eval_binary_constant(a_val, b_val));
        }
        if (op_type == DPNOpType::Add || op_type == DPNOpType::Sub) && b_type == DPNOpType::Constant && b.get_constant_value() == 0 {
            return a;
        }
        if op_type == DPNOpType::Mul
            && (a_type == DPNOpType::Constant && a.get_constant_value() == 0 || b_type == DPNOpType::Constant && b.get_constant_value() == 0)
        {
            return a;
        }
        let value = SymFeltRefValue {
            op_type,
            const_param: 0,
            inputs: vec![a, b],
        };
        self.store.insert(value)
    }

    fn op_std_binary_op_u32(&mut self, op_type: DPNOpType, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        let a_type = a.get_op_type();
        let b_type = b.get_op_type();
        if a_type == DPNOpType::ConstantU32 && b_type == DPNOpType::ConstantU32 {
            let a_val = a.get_constant_value();
            let b_val = b.get_constant_value();

            assert!(a_val <= 0xffffffffu64);
            assert!(b_val <= 0xffffffffu64);
            assert!(
                op_type.eval_binary_constant(a_val, b_val) <= 0xffffffffu64,
                "u32 op `{}` overflow",
                op_type
            );
            let res = op_type.eval_binary_constant(a_val, b_val);
            let return_bool_ops = [DPNOpType::Eq, DPNOpType::Gt, DPNOpType::Gte, DPNOpType::Lt, DPNOpType::Lte];
            if return_bool_ops.contains(&op_type) {
                return self.op_const(res);
            }
            return self.op_const_u32(res as u32);
        }
        let value = SymFeltRefValue {
            op_type,
            const_param: 0,
            inputs: vec![a, b],
        };
        self.store.insert(value)
    }

    fn op_std_unary_op(&mut self, op_type: DPNOpType, a: SymFeltRef) -> SymFeltRef {
        let a_type = a.get_op_type();
        if a_type == DPNOpType::Constant || a_type == DPNOpType::ConstantTrue || a_type == DPNOpType::ConstantFalse {
            let a_val = a.get_constant_value();
            return self.op_const(op_type.eval_unary_constant(a_val));
        }
        let value = SymFeltRefValue {
            op_type,
            const_param: 0,
            inputs: vec![a],
        };
        self.store.insert(value)
    }

    fn op_valueless(&mut self, op_type: DPNOpType) -> SymFeltRef {
        SymFeltRef::new_valueless(op_type)
    }

    fn op_target_at(&mut self, parent: SymFeltRef, index: u64) -> SymFeltRef {
        let value = SymFeltRefValue {
            op_type: DPNOpType::TargetAt,
            const_param: index,
            inputs: vec![parent, SymFeltRef::new_constant(index)],
        };
        self.store.insert(value)
    }

    fn op_target_at_vec(&mut self, parent: SymFeltRef, length: u64) -> Vec<SymFeltRef> {
        (0..length).map(|i| self.op_target_at(parent, i)).collect()
    }

    fn op_target_at_array<const N: usize>(&mut self, parent: SymFeltRef) -> [SymFeltRef; N] {
        core::array::from_fn(|i| self.op_target_at(parent, i as u64))
    }
}

impl DPNContext<SymFeltRef> for QExecContext {
    fn get_constant_value(&self, a: SymFeltRef) -> u64 {
        a.get_constant_value()
    }

    fn get_op_type(&self, a: SymFeltRef) -> DPNOpType {
        a.get_op_type()
    }

    fn op_cast_u32(&mut self, a: SymFeltRef) -> SymFeltRef {
        let op_type = a.get_op_type();

        if op_type.get_data_type() == DPNBuiltInDataType::U32Target {
            return a;
        }

        if op_type == DPNOpType::Constant
            || op_type == DPNOpType::ConstantTrue
            || op_type == DPNOpType::ConstantFalse
            || op_type == DPNOpType::ConstantU32
        {
            let value = a.get_constant_value();
            assert!(value <= 0xffffffffu64, "invalid u32 value {}", value);
            self.op_const_u32((value & 0xffffffffu64) as u32)
        } else {
            let value = SymFeltRefValue {
                op_type: DPNOpType::CastU32,
                const_param: 0,
                inputs: vec![a],
            };
            self.store.insert(value)
        }
    }

    fn op_cast_felt(&mut self, a: SymFeltRef) -> SymFeltRef {
        let op_type = a.get_op_type();

        if op_type.get_data_type() == DPNBuiltInDataType::Target {
            return a;
        }

        if op_type == DPNOpType::Constant
            || op_type == DPNOpType::ConstantTrue
            || op_type == DPNOpType::ConstantFalse
            || op_type == DPNOpType::ConstantU32
        {
            self.op_const(a.get_constant_value())
        } else {
            let value = SymFeltRefValue {
                op_type: DPNOpType::CastFelt,
                const_param: 0,
                inputs: vec![a],
            };
            self.store.insert(value)
        }
    }

    fn op_cast_bool(&mut self, a: SymFeltRef) -> SymFeltRef {
        let op_type = a.get_op_type();

        if op_type.get_data_type() == DPNBuiltInDataType::Bool {
            return a;
        }

        if op_type == DPNOpType::Constant
            || op_type == DPNOpType::ConstantTrue
            || op_type == DPNOpType::ConstantFalse
            || op_type == DPNOpType::ConstantU32
        {
            let value = a.get_constant_value();
            if value == 0 {
                SymFeltRef::constant_false()
            } else if value == 1 {
                SymFeltRef::constant_true()
            } else {
                panic!("invalid bool value {}", value);
            }
        } else {
            let value = SymFeltRefValue {
                op_type: DPNOpType::CastBool,
                const_param: 0,
                inputs: vec![a],
            };
            self.store.insert(value)
        }
    }

    fn op_select(&mut self, condition: SymFeltRef, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        let condition_type = condition.get_op_type();
        if a.eq(&b) {
            a
        } else if condition_type == DPNOpType::ConstantTrue {
            a
        } else if condition_type == DPNOpType::ConstantFalse {
            b
        } else if condition_type == DPNOpType::Constant {
            let condition_val = condition.get_constant_value();
            if condition_val == 0 {
                b
            } else {
                a
            }
        } else {
            let value = SymFeltRefValue {
                op_type: DPNOpType::Select,
                const_param: 0,
                inputs: vec![condition, a, b],
            };
            self.store.insert(value)
        }
    }

    fn op_const(&mut self, value: u64) -> SymFeltRef {
        SymFeltRef::new_constant(value)
    }

    fn op_const_u32(&mut self, value: u32) -> SymFeltRef {
        SymFeltRef::new_constant_u32(value)
    }

    fn op_bool_not(&mut self, a: SymFeltRef) -> SymFeltRef {
        self.op_std_unary_op(DPNOpType::BoolNot, a)
    }

    fn op_bool_and(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        if a.get_op_type() == DPNOpType::ConstantU32 && b.get_op_type() == DPNOpType::ConstantU32 {
            return self.op_std_binary_op_u32(DPNOpType::BoolAnd, a, b);
        }
        self.op_std_binary_op(DPNOpType::BoolAnd, a, b)
    }

    fn op_bool_or(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        if a.get_op_type() == DPNOpType::ConstantU32 && b.get_op_type() == DPNOpType::ConstantU32 {
            return self.op_std_binary_op_u32(DPNOpType::BoolOr, a, b);
        }
        self.op_std_binary_op(DPNOpType::BoolOr, a, b)
    }

    fn op_bool_or_many(&mut self, values: &[SymFeltRef]) -> SymFeltRef {
        let mut result = values[0];
        for i in 1..values.len() {
            result = self.op_bool_or(result, values[i]);
        }
        result
    }

    fn op_bool_and_many(&mut self, values: &[SymFeltRef]) -> SymFeltRef {
        let mut result = values[0];
        for i in 1..values.len() {
            result = self.op_bool_and(result, values[i]);
        }
        result
    }

    fn op_bool_xor(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        if a.get_op_type() == DPNOpType::ConstantU32 && b.get_op_type() == DPNOpType::ConstantU32 {
            return self.op_std_binary_op_u32(DPNOpType::Xor, a, b);
        }
        self.op_std_binary_op(DPNOpType::Xor, a, b)
    }

    fn op_add(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        if a.get_op_type() == DPNOpType::ConstantU32 && b.get_op_type() == DPNOpType::ConstantU32 {
            return self.op_std_binary_op_u32(DPNOpType::U32Add, a, b);
        }
        self.op_std_binary_op(DPNOpType::Add, a, b)
    }

    fn op_sub(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        if a.get_op_type() == DPNOpType::ConstantU32 && b.get_op_type() == DPNOpType::ConstantU32 {
            return self.op_std_binary_op_u32(DPNOpType::U32Sub, a, b);
        }
        self.op_std_binary_op(DPNOpType::Sub, a, b)
    }

    fn op_mul(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        if a.get_op_type() == DPNOpType::ConstantU32 && b.get_op_type() == DPNOpType::ConstantU32 {
            return self.op_std_binary_op_u32(DPNOpType::U32Mul, a, b);
        }
        self.op_std_binary_op(DPNOpType::Mul, a, b)
    }

    fn op_div(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        if a.get_op_type() == DPNOpType::ConstantU32 && b.get_op_type() == DPNOpType::ConstantU32 {
            return self.op_std_binary_op_u32(DPNOpType::U32Div, a, b);
        }
        self.op_std_binary_op(DPNOpType::Div, a, b)
    }

    fn op_u32_add(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        self.op_std_binary_op_u32(DPNOpType::U32Add, a, b)
    }

    fn op_u32_sub(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        self.op_std_binary_op_u32(DPNOpType::U32Sub, a, b)
    }

    fn op_u32_mul(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        self.op_std_binary_op_u32(DPNOpType::U32Mul, a, b)
    }

    fn op_u32_div(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        self.op_std_binary_op_u32(DPNOpType::U32Div, a, b)
    }

    fn op_mod(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        self.op_std_binary_op(DPNOpType::Mod, a, b)
    }

    fn op_exp(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        if a.get_op_type() == DPNOpType::ConstantU32 {
            return self.op_std_binary_op_u32(DPNOpType::ExpConstantBase, a, b);
        } else if b.get_op_type() == DPNOpType::ConstantU32 {
            return self.op_std_binary_op_u32(DPNOpType::ExpConstantPower, a, b);
        }
        self.op_std_binary_op(DPNOpType::Exp, a, b)
    }

    fn op_u32_mod(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        self.op_std_binary_op_u32(DPNOpType::U32Mod, a, b)
    }

    fn op_u32_exp(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        self.op_std_binary_op_u32(DPNOpType::U32Exp, a, b)
    }

    fn op_eq(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        if a.get_op_type() == DPNOpType::ConstantU32 && b.get_op_type() == DPNOpType::ConstantU32 {
            return self.op_std_binary_op_u32(DPNOpType::Eq, a, b);
        }
        self.op_std_binary_op(DPNOpType::Eq, a, b)
    }

    fn op_neq(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        let eq = if a.get_op_type() == DPNOpType::ConstantU32 && b.get_op_type() == DPNOpType::ConstantU32 {
            self.op_std_binary_op_u32(DPNOpType::Eq, a, b)
        } else {
            self.op_std_binary_op(DPNOpType::Eq, a, b)
        };
        self.op_bool_not(eq)
    }

    fn op_lt(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        if a.get_op_type() == DPNOpType::ConstantU32 && b.get_op_type() == DPNOpType::ConstantU32 {
            return self.op_std_binary_op_u32(DPNOpType::Lt, a, b);
        }
        self.op_std_binary_op(DPNOpType::Lt, a, b)
    }

    fn op_lte(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        if a.get_op_type() == DPNOpType::ConstantU32 && b.get_op_type() == DPNOpType::ConstantU32 {
            return self.op_std_binary_op_u32(DPNOpType::Lte, a, b);
        }
        self.op_std_binary_op(DPNOpType::Lte, a, b)
    }

    fn op_gt(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        if a.get_op_type() == DPNOpType::ConstantU32 && b.get_op_type() == DPNOpType::ConstantU32 {
            return self.op_std_binary_op_u32(DPNOpType::Gt, a, b);
        }
        self.op_std_binary_op(DPNOpType::Gt, a, b)
    }

    fn op_gte(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        if a.get_op_type() == DPNOpType::ConstantU32 && b.get_op_type() == DPNOpType::ConstantU32 {
            return self.op_std_binary_op_u32(DPNOpType::Gte, a, b);
        }
        self.op_std_binary_op(DPNOpType::Gte, a, b)
    }

    fn op_neg(&mut self, a: SymFeltRef) -> SymFeltRef {
        self.op_std_unary_op(DPNOpType::UnaryNegative, a)
    }

    fn op_u32_xor(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        self.op_std_binary_op_u32(DPNOpType::U32Xor, a, b)
    }

    fn op_u32_or(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        self.op_std_binary_op_u32(DPNOpType::U32Or, a, b)
    }

    fn op_u32_and(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        self.op_std_binary_op_u32(DPNOpType::U32And, a, b)
    }

    fn op_u32_shl(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        if a.get_op_type() == DPNOpType::ConstantU32 {
            return self.op_std_binary_op_u32(DPNOpType::U32ShiftLeftConstantValue, a, b);
        }
        if b.get_op_type() == DPNOpType::ConstantU32 {
            return self.op_std_binary_op_u32(DPNOpType::U32ShiftLeftConstantBitDistance, a, b);
        }
        self.op_std_binary_op_u32(DPNOpType::U32ShiftLeft, a, b)
    }

    fn op_u32_shr(&mut self, a: SymFeltRef, b: SymFeltRef) -> SymFeltRef {
        if a.get_op_type() == DPNOpType::ConstantU32 {
            return self.op_std_binary_op_u32(DPNOpType::U32ShiftRightConstantValue, a, b);
        }
        if b.get_op_type() == DPNOpType::ConstantU32 {
            return self.op_std_binary_op_u32(DPNOpType::U32ShiftRightConstantBitDistance, a, b);
        }
        self.op_std_binary_op_u32(DPNOpType::U32ShiftRight, a, b)
    }

    fn op_true(&mut self) -> SymFeltRef {
        self.op_valueless(DPNOpType::ConstantTrue)
    }

    fn op_false(&mut self) -> SymFeltRef {
        self.op_valueless(DPNOpType::ConstantFalse)
    }

    fn add_input(&mut self) -> SymFeltRef {
        let input = SymFeltRef::new_input(self.input_count, DPNBuiltInDataType::Target);
        self.input_count += 1;
        self.input_types.push(DPNBuiltInDataType::Target);
        input
    }

    fn add_u32_input(&mut self) -> SymFeltRef {
        let input = SymFeltRef::new_input(self.input_count, DPNBuiltInDataType::U32Target);
        self.input_count += 1;
        self.input_types.push(DPNBuiltInDataType::U32Target);
        input
    }

    fn add_bool_input(&mut self) -> SymFeltRef {
        let input = SymFeltRef::new_input(self.input_count, DPNBuiltInDataType::Bool);
        self.input_count += 1;
        self.input_types.push(DPNBuiltInDataType::Bool);
        input
    }

    fn add_inputs(&mut self, count: u64) -> Vec<SymFeltRef> {
        (0..count).map(|_| self.add_input()).collect()
    }

    fn assert_eq(&mut self, left: SymFeltRef, right: SymFeltRef, message: &'static str) {
        if self.condition_stack.is_empty() {
            self.assertions.push(SymRefAssertion { left, right, message });
        } else {
            let op_type = self.current_condition.get_op_type();
            if op_type == DPNOpType::ConstantTrue {
                self.assertions.push(SymRefAssertion { left, right, message });
            } else if op_type == DPNOpType::ConstantFalse {
            } else {
                let condition = self.current_condition;
                let cond_left = self.op_select(condition, left, right);
                self.assertions.push(SymRefAssertion {
                    left: cond_left,
                    right,
                    message,
                });
            }
        }
    }

    fn assert_true(&mut self, left: SymFeltRef, message: &'static str) {
        self.assert_eq(left, SymFeltRef::new_valueless(DPNOpType::ConstantTrue), message);
    }

    fn cset<V: ToFelts<SymFeltRef>>(&mut self, old_value: V, new_value: V) -> V {
        if self.condition_stack.is_empty() {
            new_value
        } else {
            let old_felts = old_value.to_felts();
            let new_felts = new_value.to_felts();
            let op_type = self.current_condition.get_op_type();
            let result_felts = if op_type == DPNOpType::ConstantTrue {
                new_felts
            } else if op_type == DPNOpType::ConstantFalse {
                old_felts
            } else {
                let condition = self.current_condition;
                old_felts
                    .into_iter()
                    .zip(new_felts.into_iter())
                    .map(|(old, new)| self.op_select(condition, new, old))
                    .collect::<Vec<_>>()
            };
            V::from_felts(&result_felts)
        }
    }

    fn start_if_block(&mut self, condition: SymFeltRef) {
        self.condition_stack.push(IfConditionStack {
            conditions: vec![condition],
            current_condition: condition,
        });
        self.current_condition = self.resolve_current_condition();
    }

    fn start_else_if_block(&mut self, condition: SymFeltRef) {
        if self.condition_stack.is_empty() {
            panic!("Cannot add else if block without starting an if block first");
        }
        let last_conditions = self.condition_stack.last().unwrap().conditions.clone();
        let one_of_prev_true = self.op_bool_or_many(&last_conditions);
        let all_prev_not_true = self.op_bool_not(one_of_prev_true);
        let new_condition = self.op_bool_and(all_prev_not_true, condition);
        self.condition_stack.last_mut().unwrap().conditions.push(condition);
        self.condition_stack.last_mut().unwrap().current_condition = new_condition;
        self.current_condition = self.resolve_current_condition();
    }

    fn start_else_block(&mut self) {
        if self.condition_stack.is_empty() {
            panic!("Cannot add else block without starting an if block first");
        }
        let last_conditions = self.condition_stack.last().unwrap().conditions.clone();
        let one_of_prev_true = self.op_bool_or_many(&last_conditions);
        let all_prev_not_true = self.op_bool_not(one_of_prev_true);
        self.condition_stack.last_mut().unwrap().current_condition = all_prev_not_true;
        self.current_condition = self.resolve_current_condition();
    }

    fn end_if_block(&mut self) {
        if self.condition_stack.is_empty() {
            panic!("Cannot end if block without starting an if block first");
        }
        self.condition_stack.pop();
        self.current_condition = self.resolve_current_condition();
    }

    fn resolve_current_condition(&mut self) -> SymFeltRef {
        if self.condition_stack.is_empty() {
            self.op_true()
        } else {
            let conditions = self.condition_stack.iter().map(|x| x.current_condition).collect::<Vec<_>>();
            self.op_bool_and_many(&conditions)
        }
    }

    fn get_current_condition(&self) -> SymFeltRef {
        if self.condition_stack.is_empty() {
            SymFeltRef::constant_true()
        } else {
            let op_type = self.current_condition.get_op_type();
            if op_type == DPNOpType::ConstantTrue {
                SymFeltRef::constant_true()
            } else if op_type == DPNOpType::ConstantFalse {
                SymFeltRef::constant_false()
            } else {
                self.current_condition
            }
        }
    }

    fn hash(&mut self, values: &[SymFeltRef]) -> [SymFeltRef; 4] {
        let op = SymFeltRefValue {
            op_type: DPNOpType::HashNoPad,
            const_param: 0,
            inputs: values.to_vec(),
        };
        let parent = self.store.insert(op);
        self.op_target_at_array::<4>(parent)
    }

    fn hash_two_to_one(&mut self, left: &[SymFeltRef; 4], right: &[SymFeltRef; 4]) -> [SymFeltRef; 4] {
        let mut inputs = Vec::new();
        inputs.extend_from_slice(left);
        inputs.extend_from_slice(right);
        let op = SymFeltRefValue {
            op_type: DPNOpType::HashTwoToOne,
            const_param: 0,
            inputs,
        };
        let parent = self.store.insert(op);
        self.op_target_at_array::<4>(parent)
    }

    fn keccak256(&mut self, values: &[SymFeltRef]) -> [SymFeltRef; 8] {
        let op = SymFeltRefValue {
            op_type: DPNOpType::Keccak256,
            const_param: 0,
            inputs: values.to_vec(),
        };
        let parent = self.store.insert(op);
        self.op_target_at_array::<8>(parent)
    }

    fn split_bits(&mut self, value: SymFeltRef, num_bits: u64) -> Vec<SymFeltRef> {
        let num_bits_ref = self.op_const(num_bits);
        let op = SymFeltRefValue {
            op_type: DPNOpType::SplitBits,
            const_param: num_bits,
            inputs: vec![value, num_bits_ref],
        };
        let parent = self.store.insert(op);
        self.op_target_at_vec(parent, num_bits)
    }

    fn sum_bits(&mut self, bits: &[SymFeltRef]) -> SymFeltRef {
        let op = SymFeltRefValue {
            op_type: DPNOpType::SumBits,
            const_param: 0,
            inputs: bits.to_vec(),
        };
        self.store.insert(op)
    }

    fn op_secp256k1_verify(&mut self, public_key: [SymFeltRef; 16], msg_hash: [SymFeltRef; 4], signature: [SymFeltRef; 16]) -> SymFeltRef {
        let inputs: Vec<_> = public_key.into_iter().chain(signature.into_iter()).chain(msg_hash.into_iter()).collect();

        let value = SymFeltRefValue {
            op_type: DPNOpType::Secp256k1Verify,
            const_param: 0,
            inputs,
        };
        self.store.insert(value)
    }

    fn get_user_id(&mut self) -> SymFeltRef {
        SymFeltRef::new_valueless(DPNOpType::GetUserId)
    }

    fn get_contract_id(&mut self) -> SymFeltRef {
        SymFeltRef::new_valueless(DPNOpType::GetContractId)
    }

    fn get_contract_deployer(&mut self, contract_id: SymFeltRef) -> [SymFeltRef; 4] {
        let cmd = DPNStateCmd::GetContractLeaf(DPNStateCmdGetContractLeaf { contract_id });
        let b = self.resolve_state_cmd_base(cmd);
        self.op_target_at_array::<4>(b)
    }

    fn get_contract_state_tree_height(&mut self, contract_id: SymFeltRef) -> SymFeltRef {
        let cmd = DPNStateCmd::GetContractLeaf(DPNStateCmdGetContractLeaf { contract_id });
        let contract_leaf = self.resolve_state_cmd_base(cmd);
        self.op_target_at(contract_leaf, 12)
    }

    fn get_caller_contract_id(&mut self) -> SymFeltRef {
        SymFeltRef::new_valueless(DPNOpType::GetCallerContractId)
    }

    fn get_checkpoint_id(&mut self) -> SymFeltRef {
        SymFeltRef::new_valueless(DPNOpType::GetCheckpointId)
    }

    fn get_last_nonce(&mut self) -> SymFeltRef {
        SymFeltRef::new_valueless(DPNOpType::GetNonce)
    }

    fn get_user_public_key_hash(&mut self) -> [SymFeltRef; 4] {
        self.op_target_at_array(SymFeltRef::new_valueless(DPNOpType::GetUserPublicKeyHash))
    }

    fn get_session_proof_tree_root(&mut self) -> [SymFeltRef; 4] {
        self.op_target_at_array(SymFeltRef::new_valueless(DPNOpType::GetSessionProofTreeRoot))
    }

    fn get_checkpoint_stats(&mut self, checkpoint_id: SymFeltRef) -> Vec<SymFeltRef> {
        let cmd = DPNStateCmd::GetCheckpointLeafStats(DPNStateCmdGetCheckpointLeafStats { checkpoint_id });
        let b = self.resolve_state_cmd_base(cmd);
        let mut result = Vec::new();
        let stats_size = PsyCheckpointLeafStats::<GoldilocksField>::q_felt_size();
        for i in 0..stats_size {
            result.push(self.op_target_at(b, i as u64));
        }
        result
    }

    fn get_register_users_root(&mut self, checkpoint_id: SymFeltRef) -> [SymFeltRef; 4] {
        let stats = self.get_checkpoint_stats(checkpoint_id);
        [stats[13].clone(), stats[14].clone(), stats[15].clone(), stats[16].clone()]
    }

    fn get_gutas_root(&mut self, checkpoint_id: SymFeltRef) -> [SymFeltRef; 4] {
        let stats = self.get_checkpoint_stats(checkpoint_id);
        [stats[17].clone(), stats[18].clone(), stats[19].clone(), stats[20].clone()]
    }

    fn get_deploy_contracts_root(&mut self, checkpoint_id: SymFeltRef) -> [SymFeltRef; 4] {
        let stats = self.get_checkpoint_stats(checkpoint_id);
        [stats[21].clone(), stats[22].clone(), stats[23].clone(), stats[24].clone()]
    }

    fn get_guta_fees_collected(&mut self, checkpoint_id: SymFeltRef) -> SymFeltRef {
        let stats = self.get_checkpoint_stats(checkpoint_id);
        stats[0].clone()
    }

    fn get_da_fees_collected(&mut self, checkpoint_id: SymFeltRef) -> SymFeltRef {
        let stats = self.get_checkpoint_stats(checkpoint_id);
        stats[1].clone()
    }

    fn get_user_ops_processed(&mut self, checkpoint_id: SymFeltRef) -> SymFeltRef {
        let stats = self.get_checkpoint_stats(checkpoint_id);
        stats[2].clone()
    }

    fn get_total_transactions(&mut self, checkpoint_id: SymFeltRef) -> SymFeltRef {
        let stats = self.get_checkpoint_stats(checkpoint_id);
        stats[3].clone()
    }

    fn get_slots_modified(&mut self, checkpoint_id: SymFeltRef) -> SymFeltRef {
        let stats = self.get_checkpoint_stats(checkpoint_id);
        stats[4].clone()
    }

    fn get_deploy_contracts_completed(&mut self, checkpoint_id: SymFeltRef) -> SymFeltRef {
        let stats = self.get_checkpoint_stats(checkpoint_id);
        stats[5].clone()
    }

    fn get_register_users_completed(&mut self, checkpoint_id: SymFeltRef) -> SymFeltRef {
        let stats = self.get_checkpoint_stats(checkpoint_id);
        stats[6].clone()
    }

    fn get_gutas_completed(&mut self, checkpoint_id: SymFeltRef) -> SymFeltRef {
        let stats = self.get_checkpoint_stats(checkpoint_id);
        stats[7].clone()
    }

    fn get_global_state_roots(&mut self, checkpoint_id: SymFeltRef) -> Vec<SymFeltRef> {
        let cmd = DPNStateCmd::GetGlobalStateRoots(DPNStateCmdGetGlobalStateRoots { checkpoint_id });
        let b = self.resolve_state_cmd_base(cmd);
        let mut result = Vec::new();
        let roots_size = PsyCheckpointGlobalStateRoots::<GoldilocksField>::q_felt_size();
        for i in 0..roots_size {
            result.push(self.op_target_at(b, i as u64));
        }
        result
    }

    fn get_checkpoint_contract_tree_root(&mut self, checkpoint_id: SymFeltRef) -> [SymFeltRef; 4] {
        let roots = self.get_global_state_roots(checkpoint_id);
        [roots[0].clone(), roots[1].clone(), roots[2].clone(), roots[3].clone()]
    }

    fn get_checkpoint_deposit_tree_root(&mut self, checkpoint_id: SymFeltRef) -> [SymFeltRef; 4] {
        let roots = self.get_global_state_roots(checkpoint_id);
        [roots[4].clone(), roots[5].clone(), roots[6].clone(), roots[7].clone()]
    }

    fn get_checkpoint_user_tree_root(&mut self, checkpoint_id: SymFeltRef) -> [SymFeltRef; 4] {
        let roots = self.get_global_state_roots(checkpoint_id);
        [roots[8].clone(), roots[9].clone(), roots[10].clone(), roots[11].clone()]
    }

    fn get_checkpoint_withdrawal_tree_root(&mut self, checkpoint_id: SymFeltRef) -> [SymFeltRef; 4] {
        let roots = self.get_global_state_roots(checkpoint_id);
        [roots[12].clone(), roots[13].clone(), roots[14].clone(), roots[15].clone()]
    }

    fn get_checkpoint_user_registration_tree_root(&mut self, checkpoint_id: SymFeltRef) -> [SymFeltRef; 4] {
        let roots = self.get_global_state_roots(checkpoint_id);
        [roots[16].clone(), roots[17].clone(), roots[18].clone(), roots[19].clone()]
    }

    fn op_get_state_felt(
        &mut self,
        contract_state_tree_height: SymFeltRef,
        contract_id: SymFeltRef,
        user_id: SymFeltRef,
        index: SymFeltRef,
    ) -> SymFeltRef {
        self.create_contract_state_get_ref(contract_state_tree_height, contract_id, user_id, index, 1)
    }

    fn op_set_state_felt(&mut self, index: SymFeltRef, value: SymFeltRef) -> SymFeltRef {
        let core_ref = self.op_get_state_felt(
            SymFeltRef::new_constant(self.contract_state_tree_height as u64),
            SymFeltRef::new_valueless(DPNOpType::GetContractId),
            SymFeltRef::new_valueless(DPNOpType::GetUserId),
            index,
        );
        if core_ref.eq(&value) {
            return value;
        }
        let condition = self.get_current_condition();
        if condition.eq(&SymFeltRef::constant_false()) {
            self.op_get_state_felt(
                SymFeltRef::new_constant(self.contract_state_tree_height as u64),
                SymFeltRef::new_valueless(DPNOpType::GetContractId),
                SymFeltRef::new_valueless(DPNOpType::GetUserId),
                index,
            )
        } else {
            self.create_contract_state_ref(
                self.contract_state_tree_height,
                SymFeltRef::new_valueless(DPNOpType::GetContractId),
                SymFeltRef::new_valueless(DPNOpType::GetUserId),
                condition,
                index,
                vec![value],
            )
        }
    }

    fn op_set_state_obj<T: ToFelts<SymFeltRef>>(&mut self, index: SymFeltRef, value: T) -> T {
        let felts = value.to_felts();
        let condition = self.get_current_condition();

        self.create_contract_state_ref(
            self.contract_state_tree_height,
            SymFeltRef::new_valueless(DPNOpType::GetContractId),
            SymFeltRef::new_valueless(DPNOpType::GetUserId),
            condition,
            index,
            felts,
        );
        value
    }

    fn clear_entire_tree(&mut self) -> Vec<SymFeltRef> {
        let condition = self.get_current_condition();

        let cmd = DPNStateCmd::ClearEntireTree(DPNStateCmdClearEntireTree { condition });
        let b = self.resolve_state_cmd_base(cmd);
        let mut result = Vec::new();
        for i in 0..4 {
            result.push(self.op_target_at(b, i as u64));
        }
        result
    }

    fn cset_state<V: ToFelts<SymFeltRef>>(&mut self, old_value: V, new_value: V) -> V {
        let old_felts = old_value.to_felts();
        for old in old_felts.iter() {
            if old.get_op_type() != DPNOpType::GetStateQueryResultSingle && old.get_op_type() != DPNOpType::GetStateCommandResultArray {
                panic!("cset_state can only be used with state objects");
            }
        }
        let start_index = self.store.get_direct_children(old_felts[0])[2];
        self.op_set_state_obj(start_index, new_value)
    }

    fn cset_state_at<V: ToFelts<SymFeltRef>>(&mut self, sub_index: SymFeltRef, new_value: V) -> V {
        self.op_set_state_obj(sub_index, new_value)
    }

    fn cinvoke_external_contract_function_sync(
        &mut self,
        contract_id: SymFeltRef,
        method_id: SymFeltRef,
        input_args: Vec<SymFeltRef>,
        num_outputs: u32,
    ) -> Vec<SymFeltRef> {
        let condition = self.get_current_condition();

        let b = self.resolve_state_cmd_base(DPNStateCmd::InvokeExternalContractFunctionSync(
            DPNStateCmdInvokeExternalContractFunctionSync {
                condition,
                contract_id,
                method_id,
                input_args,
                num_outputs,
            },
        ));
        self.op_target_at_vec(b, num_outputs as u64)
    }

    fn cinvoke_external_contract_function_deferred(
        &mut self,
        contract_id: SymFeltRef,
        method_id: SymFeltRef,
        input_args: Vec<SymFeltRef>,
    ) -> [SymFeltRef; 4] {
        let condition = self.get_current_condition();

        let b = self.resolve_state_cmd_base(DPNStateCmd::InvokeExternalContractFunctionDeferred(
            DPNStateCmdInvokeExternalContractFunctionDeferred {
                condition,
                contract_id,
                method_id,
                input_args,
            },
        ));
        [
            self.op_target_at(b, 0),
            self.op_target_at(b, 1),
            self.op_target_at(b, 2),
            self.op_target_at(b, 3),
        ]
    }

    fn cset_state_hash_at(&mut self, slot_index: SymFeltRef, new_value: [SymFeltRef; 4]) -> [SymFeltRef; 4] {
        let condition = self.get_current_condition();

        self.resolve_state_cmd_base(DPNStateCmd::SetContractStateSlotHash(DPNStateCmdSetContractStateSlotHash {
            value: new_value,
            condition,
            slot_index,
        }));
        new_value
    }

    fn get_state_hash_at(&mut self, slot_index: SymFeltRef) -> [SymFeltRef; 4] {
        let b = self.resolve_state_cmd_base(DPNStateCmd::GetSelfUserCurrentContractStateSlotHash(
            DPNStateCmdGetSelfUserCurrentContractStateSlotHash { slot_index },
        ));
        [
            self.op_target_at(b, 0),
            self.op_target_at(b, 1),
            self.op_target_at(b, 2),
            self.op_target_at(b, 3),
        ]
    }

    fn get_other_contract_state_hash_at(
        &mut self,
        contract_state_tree_height: SymFeltRef,
        contract_id: SymFeltRef,
        slot_index: SymFeltRef,
    ) -> [SymFeltRef; 4] {
        let contract_state_tree_height = if contract_id.get_op_type() == DPNOpType::GetContractId {
            SymFeltRef::new_constant(self.contract_state_tree_height as u64)
        } else {
            contract_state_tree_height
        };

        let b = self.resolve_state_cmd_base(DPNStateCmd::GetSelfUserExternalContractStateSlotHash(
            DPNStateCmdGetSelfUserExternalContractStateSlotHash {
                slot_index,
                contract_id,
                contract_state_tree_height,
            },
        ));
        [
            self.op_target_at(b, 0),
            self.op_target_at(b, 1),
            self.op_target_at(b, 2),
            self.op_target_at(b, 3),
        ]
    }

    fn get_other_user_contract_state_hash_at(
        &mut self,
        contract_state_tree_height: SymFeltRef,
        user_id: SymFeltRef,
        contract_id: SymFeltRef,
        slot_index: SymFeltRef,
    ) -> [SymFeltRef; 4] {
        let contract_state_tree_height = if contract_id.get_op_type() == DPNOpType::GetContractId {
            SymFeltRef::new_constant(self.contract_state_tree_height as u64)
        } else {
            contract_state_tree_height
        };
        let b = self.resolve_state_cmd_base(DPNStateCmd::GetOtherUserContractStateSlotHash(
            DPNStateCmdGetOtherUserContractStateSlotHash {
                slot_index,
                user_id,
                contract_id,
                contract_state_tree_height,
            },
        ));
        [
            self.op_target_at(b, 0),
            self.op_target_at(b, 1),
            self.op_target_at(b, 2),
            self.op_target_at(b, 3),
        ]
    }

    fn get_state_range_at(&mut self, sub_slot_index: SymFeltRef, length: SymFeltRef) -> Vec<SymFeltRef> {
        assert!(length.is_constant_type(), "range length must be constant");
        let b = self.create_contract_state_get_ref(
            SymFeltRef::new_constant(self.contract_state_tree_height as u64),
            SymFeltRef::new_valueless(DPNOpType::GetContractId),
            SymFeltRef::new_valueless(DPNOpType::GetUserId),
            sub_slot_index,
            length.get_constant_value() as u32,
        );
        self.op_target_at_vec(b, length.get_constant_value() as u64)
    }

    fn get_other_user_contract_state_range_at(
        &mut self,
        contract_state_tree_height: SymFeltRef,
        user_id: SymFeltRef,
        contract_id: SymFeltRef,
        sub_slot_index: SymFeltRef,
        length: SymFeltRef,
    ) -> Vec<SymFeltRef> {
        let contract_state_tree_height = if contract_id.get_op_type() == DPNOpType::GetContractId {
            SymFeltRef::new_constant(self.contract_state_tree_height as u64)
        } else {
            contract_state_tree_height
        };
        assert!(length.is_constant_type(), "range length must be constant");
        let b = self.create_contract_state_get_ref(
            contract_state_tree_height,
            contract_id,
            user_id,
            sub_slot_index,
            length.get_constant_value() as u32,
        );
        self.op_target_at_vec(b, length.get_constant_value() as u64)
    }

    fn cset_state_range_at(&mut self, sub_slot_index: SymFeltRef, values: &[SymFeltRef]) {
        let condition = self.get_current_condition();

        self.create_contract_state_ref(
            self.contract_state_tree_height,
            SymFeltRef::new_valueless(DPNOpType::GetContractId),
            SymFeltRef::new_valueless(DPNOpType::GetUserId),
            condition,
            sub_slot_index,
            values.to_vec(),
        );
    }
    // ─── IMT (Indexed Merkle Tree) state commands ─────────────────────────

    /// Get a value from the IMT by 256-bit key (self user, current contract).
    /// Returns the 4-element hash value.
    fn imt_get_value(&mut self, key: [SymFeltRef; 4], base_offset: SymFeltRef, capacity: SymFeltRef) -> [SymFeltRef; 4] {
        let b = self.resolve_state_cmd_base(DPNStateCmd::get_self_user_current_imt_contract_state_value(base_offset, capacity, key));
        [
            self.op_target_at(b, 0),
            self.op_target_at(b, 1),
            self.op_target_at(b, 2),
            self.op_target_at(b, 3),
        ]
    }

    fn imt_get_other_user_value(
        &mut self,
        contract_state_tree_height: SymFeltRef,
        user_id: SymFeltRef,
        contract_id: SymFeltRef,
        key: [SymFeltRef; 4],
        base_offset: SymFeltRef,
        capacity: SymFeltRef,
    ) -> [SymFeltRef; 4] {
        let contract_state_tree_height = if contract_id.get_op_type() == DPNOpType::GetContractId {
            SymFeltRef::new_constant(self.contract_state_tree_height as u64)
        } else {
            contract_state_tree_height
        };
        let b = self.resolve_state_cmd_base(DPNStateCmd::get_other_user_imt_contract_state_value(
            user_id,
            contract_id,
            contract_state_tree_height,
            base_offset,
            capacity,
            key,
        ));
        [
            self.op_target_at(b, 0),
            self.op_target_at(b, 1),
            self.op_target_at(b, 2),
            self.op_target_at(b, 3),
        ]
    }

    fn imt_contains_other_user(
        &mut self,
        contract_state_tree_height: SymFeltRef,
        user_id: SymFeltRef,
        contract_id: SymFeltRef,
        key: [SymFeltRef; 4],
        base_offset: SymFeltRef,
        capacity: SymFeltRef,
    ) -> SymFeltRef {
        let contract_state_tree_height = if contract_id.get_op_type() == DPNOpType::GetContractId {
            SymFeltRef::new_constant(self.contract_state_tree_height as u64)
        } else {
            contract_state_tree_height
        };
        let b = self.resolve_state_cmd_base(DPNStateCmd::contains_other_user_imt_contract_state_value(
            user_id,
            contract_id,
            contract_state_tree_height,
            base_offset,
            capacity,
            key,
        ));
        self.op_target_at(b, 0)
    }

    /// Insert/upsert a key-value pair into the IMT (self user, current
    /// contract). Uses the current condition for conditional execution.
    /// Returns the old value (first 4 elements of the 8-element result).
    fn imt_insert(&mut self, key: [SymFeltRef; 4], value: [SymFeltRef; 4], base_offset: SymFeltRef, capacity: SymFeltRef) -> [SymFeltRef; 4] {
        let condition = self.get_current_condition();
        let b = self.resolve_state_cmd_base(DPNStateCmd::set_imt_contract_state_value(condition, base_offset, capacity, key, value));
        // SetIMTContractStateValue returns 8 felts: old_value[4] + new_value[4]
        // Return the old_value (first 4 elements)
        [
            self.op_target_at(b, 0),
            self.op_target_at(b, 1),
            self.op_target_at(b, 2),
            self.op_target_at(b, 3),
        ]
    }

    /// Update a key-value pair in the IMT (same as insert with upsert
    /// semantics). Returns the old value.
    fn imt_update(&mut self, key: [SymFeltRef; 4], new_value: [SymFeltRef; 4], base_offset: SymFeltRef, capacity: SymFeltRef) -> [SymFeltRef; 4] {
        self.imt_insert(key, new_value, base_offset, capacity)
    }

    fn imt_contains(&mut self, key: [SymFeltRef; 4], base_offset: SymFeltRef, capacity: SymFeltRef) -> SymFeltRef {
        let b = self.resolve_state_cmd_base(DPNStateCmd::contains_self_user_current_imt_contract_state_value(
            base_offset,
            capacity,
            key,
        ));
        self.op_target_at(b, 0)
    }

    fn emit_event(&mut self, event_data: Vec<SymFeltRef>) {
        let current_condition = self.get_current_condition();
        let op_type = current_condition.get_op_type();

        if op_type == DPNOpType::ConstantFalse {
            // Condition is always false — skip event entirely
            return;
        }

        if self.condition_stack.is_empty() || op_type == DPNOpType::ConstantTrue {
            // Unconditional emit
            let event_record = EventRecord {
                condition: SymFeltRef::constant_true(),
                checkpoint_id: SymFeltRef::new_valueless(DPNOpType::GetCheckpointId),
                user_id: SymFeltRef::new_valueless(DPNOpType::GetUserId),
                contract_id: SymFeltRef::new_valueless(DPNOpType::GetContractId),
                data: event_data,
            };
            self.events.push(event_record);
        } else {
            // Conditional emit — condition is the runtime condition,
            // data fields use op_select so they resolve to zero when false
            let condition = current_condition;
            let zero = SymFeltRef::new_constant(0);
            let checkpoint_id = self.op_select(condition, SymFeltRef::new_valueless(DPNOpType::GetCheckpointId), zero);
            let user_id = self.op_select(condition, SymFeltRef::new_valueless(DPNOpType::GetUserId), zero);
            let contract_id = self.op_select(condition, SymFeltRef::new_valueless(DPNOpType::GetContractId), zero);
            let data = event_data
                .into_iter()
                .map(|v| {
                    if v.eq(&zero) {
                        v
                    } else if v.get_op_type() == DPNOpType::GetCheckpointId
                        || v.get_op_type() == DPNOpType::GetUserId
                        || v.get_op_type() == DPNOpType::GetContractId
                    {
                        // new_valueless ops also need to be conditional
                        self.op_select(condition, v, zero)
                    } else {
                        self.op_select(condition, v, zero)
                    }
                })
                .collect();
            let event_record = EventRecord {
                condition,
                checkpoint_id,
                user_id,
                contract_id,
                data,
            };
            self.events.push(event_record);
        }
    }
}
